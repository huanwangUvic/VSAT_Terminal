
//////////////////////////////////////////////////////////////////////
#ifndef HDLCFrameH
#define HDLCFrameH

class CHDLCFrame
{
public:
  unsigned char*  Data;//帧数据
  unsigned long   DataLen;//帧长度包括FCS-16

  bool   bCurFrameCorrect;  //当前帧CRC是否正确
  unsigned long   nCorrectFrames;
  unsigned long   nIncorrectFrames;

  CHDLCFrame(bool bCalculateCRC = false);
  virtual ~CHDLCFrame();

  bool GetDataBlock( unsigned char *pDataBuffer, int DataByteLen );

protected:

private:
  unsigned char * m_pBuffer;
  int   m_BufferSize;
  unsigned long   DataSize;
  int   m_ShiftByte;
  int   m_ShiftBit;
  unsigned char  OutCode;
  int   OneCount;
  int   BitCount;

  unsigned int   Count7E;

  unsigned char  ConnectByte;
  bool  m_bDataBreak;
  bool	m_bCalculateCRC;

  unsigned char *  szSwapTable;

  unsigned short nCRC;
  unsigned short * nCRCTable;

  void InitCRCtable();
  unsigned short CalculateCRC(unsigned short icrc, unsigned char *icp, unsigned int icnt ); 

  void InitSwapByteTable();
  bool Search7ECode( int Start, int End );
  int  SearchData( int Start, int End );
  bool CollectData( int Start, int End );
  unsigned char htol( unsigned char ByteData );
};

#endif
