/**
 * 该类用来解主站HDLC数据封装
 */
#include "HDLCFrame.h"
#include <iostream>
using namespace std; 

CHDLCFrame::CHDLCFrame( bool bCalculateCRC)
{
  Data = new unsigned char[2048];
  nCRCTable = new unsigned short[256];
  szSwapTable = new unsigned char[256];
  
  m_pBuffer     = 0;
  m_BufferSize  = 0;
  DataSize      = 2040;
  DataLen       = 0;
  m_ShiftByte   = 0;
  m_ShiftBit    = 0;
  m_bDataBreak  = false;
  BitCount      = 0;
  OneCount      = 0;
  ConnectByte   = 0;
  Count7E	      = 0;

  m_bCalculateCRC = bCalculateCRC;
  nCorrectFrames = 0;
  nIncorrectFrames = 0;
  bCurFrameCorrect = true;
  
  InitCRCtable();
  InitSwapByteTable();
}

CHDLCFrame::~CHDLCFrame()
{
 if (szSwapTable) delete [] szSwapTable;
 if (nCRCTable) delete [] nCRCTable;
 if (Data) delete [] Data;
}

void CHDLCFrame::InitCRCtable()
{
	short  b, v, i;
	
	for( b = 0; b <= 255; ++b )	{
		for( v = b<<(8), i = 8; --i >= 0; )
			v = v&0x8000 ? (v<<1)^0x1021 : v<<1;
		nCRCTable[b] = v;
	}
}

unsigned short CHDLCFrame::CalculateCRC(unsigned short icrc, unsigned char *icp, unsigned int icnt )
{
	register unsigned short crc = icrc;
	register unsigned char *cp = icp;
	register unsigned int cnt = icnt;
	
	while( cnt-- )
		crc = (crc<<8) ^ nCRCTable[(crc>>8) ^ *cp++];
	
	return( crc ); 
}

void CHDLCFrame::InitSwapByteTable()
{
	unsigned char cp = 255;

	szSwapTable[255] = 255;
	while (cp--) 
		szSwapTable[cp] = htol(cp);

}

unsigned char CHDLCFrame::htol( unsigned char ByteData )
{
	return ((ByteData & 0x80) >> 7) |
		((ByteData & 0x40) >> 5) |
		((ByteData & 0x20) >> 3) |
		((ByteData & 0x10) >> 1) |
		((ByteData & 0x08) << 1) |
		((ByteData & 0x04) << 3) |
		((ByteData & 0x02) << 5) |
		((ByteData & 0x01) << 7) ;
}

bool CHDLCFrame::Search7ECode( int Start, int End )
{
  unsigned char CodeBuf;
  for( int i=Start; i<(End-1); i++ ) {
    for( int k=0; k<8; k++) {
      if( i == -1 )
        CodeBuf = (ConnectByte<<k) | (m_pBuffer[0]>>(8-k));
      else
        CodeBuf = (m_pBuffer[i]<<k) | (m_pBuffer[i+1]>>(8-k));
      if( CodeBuf == 0x7E ) {
        m_ShiftByte = i;
        m_ShiftBit  = k;
        return true;
      }
    }
  }
  return false;
}

int CHDLCFrame::SearchData( int Start, int End )
{
  unsigned char  CodeBuf;

  for( int i=Start; i<(End-1); i++ ) {
    if( i == -1 )
      CodeBuf = (ConnectByte<<m_ShiftBit) | (m_pBuffer[0]>>(8-m_ShiftBit));
    else
      CodeBuf = (m_pBuffer[i]<<m_ShiftBit) | (m_pBuffer[i+1]>>(8-m_ShiftBit));

    if( CodeBuf == 0x7E ) {
      Count7E ++;
    }
    else {
      if( Count7E > 0 ) {
        m_ShiftByte = i;
        DataLen = 0;
		Count7E = 0;
        return true;
      }
      else {
        Count7E  = 0;
        if( Search7ECode( i, End ) ) {
          i = m_ShiftByte;
          Count7E ++;
        }
        else {
          m_ShiftByte = -1;
          ConnectByte  = m_pBuffer[End-1];
          return false;
        }
      }
    }
  }
  m_ShiftByte    = -1;
  ConnectByte    = m_pBuffer[End-1];
  return false;
}

bool CHDLCFrame::CollectData( int Start, int End )
{
	unsigned char CodeBuf = 0;
	unsigned char BitCode;

	for( int i=Start; i<(End-1); i++ )
	{
		if( i == -1 )
			CodeBuf = (ConnectByte<<m_ShiftBit) | (m_pBuffer[0]>>(8-m_ShiftBit));
		else
			CodeBuf = (m_pBuffer[i]<<m_ShiftBit) | (m_pBuffer[i+1]>>(8-m_ShiftBit));

		for( int k=0; k<8; k++ ) {
			BitCode = (CodeBuf>>(7-k)) & 0x01;
			if( BitCode == 1 ) {
				OneCount++;
				if( OneCount > 5 ) {
					if( (m_ShiftBit+k) < 6 )
						m_ShiftByte  = (i>=0)?(i-1):i;
					else
						if( (m_ShiftBit+k) < 14 )
							m_ShiftByte = i;
						else
							m_ShiftByte = i+1;

					if( DataLen < 2 ) m_ShiftByte += 2;

					m_ShiftBit    = (m_ShiftBit+k+2)%8;
					m_bDataBreak  = false;
					BitCount    = 0;
					OneCount    = 0;
					OutCode     = 0;
					++Count7E;

					return true;
				}
			}
			else
			{
				if( OneCount == 5 ) {
					OneCount = 0;
					continue;
				}
				OneCount = 0;
			}

			OutCode = (OutCode<<1) | BitCode;
			BitCount++;
			if( BitCount == 8 ) {
				BitCount = 0;
				Data[DataLen] =  OutCode ;
				DataLen++;
				if( DataLen > DataSize ) {
					m_ShiftByte    = i;
					m_ShiftBit    = (m_ShiftBit+k+2)%8;
					m_bDataBreak  = false;
					BitCount    = 0;
					OneCount    = 0;
					OutCode      = 0;
					return true;
				}
			}
		}
	}
	m_ShiftByte    = -1;
	ConnectByte    = m_pBuffer[End-1];
	m_bDataBreak  = true;
	return false;
}

bool CHDLCFrame::GetDataBlock( unsigned char *pDataBuffer, int DataByteLen )
{
  bool bGetData;
  unsigned char szCRC[2];
  unsigned short nCRC;
  unsigned long i;

	m_pBuffer = pDataBuffer;
  do 
  {	
	  if ( m_bDataBreak ) {
		  bGetData =  CollectData( m_ShiftByte, DataByteLen );
	  }
	  else {
		  if( SearchData( m_ShiftByte, DataByteLen) )
			  bGetData = CollectData( m_ShiftByte, DataByteLen );
		  else
			  bGetData = false;
	  }

	  if ( bGetData ) {
		  if ( m_bCalculateCRC ) {
			  if (DataLen < 5) {
				  ++nIncorrectFrames;
				  bCurFrameCorrect = false;
			  }
			  else {
				  nCRC = 0xFFFF;
				  nCRC = CalculateCRC( nCRC, Data, DataLen-2 ); 
				  szCRC[0] = ~(nCRC>>8);
				  szCRC[1] = ~(nCRC&0xFF);
				  if (szCRC[0] == Data[DataLen-2] && szCRC[1] == Data[DataLen-1]) {
					  ++nCorrectFrames;
					  bCurFrameCorrect = true;
				  }
				  else{
					  ++nIncorrectFrames;
					  bCurFrameCorrect = false;
				  }	  
			  }		  
		  }

		  for (i=0; i<DataLen; i++) {
			  Data[i] = szSwapTable[Data[i]];
		  }
	  }

  } while(bGetData && DataLen<5);

  return bGetData;
}
