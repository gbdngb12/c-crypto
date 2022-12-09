#include <stdio.h>

int gcd(int, int);

int gcd(int x, int y) {
    int remainder; 
    while(y) { //y가 0이 될 때 x가 Greastest Common Divisor, GCD 이다.
        remainder = x % y;
        x = y;
        y = remainder;
    }
    return x; //최대 공약수를 리턴한다.
}
int main() {

    return 0;
}