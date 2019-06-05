rm -f solve
gcc -O3 -lpthread blake2/*.c *.c -o solve
./solve
