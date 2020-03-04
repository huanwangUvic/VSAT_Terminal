TARGET=PPsal
CC=gcc
SRC = $(wildcard ./src/*.c)
INC = -I./include
OBJ = $(SRC:.c=.o)
LIBS=-lpthread -lnfnetlink -lnetfilter_queue -lm
CFLAGS = -Wall -O0 -g
all:depend $(TARGET) mov 
depend:
	$(CC) $(INC) -M $(SRC) > .depend
	g++ $(INC) -MM ./src/recv.cpp >> .depend
-include .depend
$(TARGET):$(OBJ) ./src/recv.o ./HDLCFrame.o
	g++ $(INC) $(LIBS) $^ -o $@
./src/recv.o : ./src/recv.cpp
	g++ $(INC) $(CFLAGS) -o $@ -c $^
./src/%.o: ./src/%.c
	$(CC) $(INC) $(CFLAGS) -o $@ -c $<
mov:
	@mv $(OBJ) ./src/recv.o ./Debug -f
clean:
	rm ./Debug/* ./src/*.o .depend -rf
