test: test.c
	gcc test.c -lssh -o test

livessh.so: livessh.c external.h external.c
	gcc -O -I. -L.-D_LINUX -D_RELEASE -DNDEBUG -DRELEASE -Xlinker -no-undefined -fno-exceptions -Wl,-Bstatic -Wl,-Bdynamic -static -shared livessh.c external.c -o livessh.so -lssh

livessh.dll: livessh.c external.h external.c
	gcc -I. -Ilibssh/include -Llibssh/bin -Llibssh/lib -D_WIN32 -D_RELEASE -DNDEBUG -DRELEASE livessh.c external.c -Xlinker -no-undefined -fno-exceptions -Wl,-Bstatic -Wl,-Bdynamic -shared  -o livessh.dll -lssh

livessh: livessh.c external.h external.c
	gcc -I. -Ilibssh/include -Llibssh/bin -Llibssh/lib -D_MACOSX -D_RELEASE -DNDEBUG -DRELEASE livessh.c external.c -Xlinker -no-undefined -fno-exceptions -Wl,-Bstatic -Wl,-Bdynamic -shared  -o livessh -lssh