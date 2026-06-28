#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int subtract(int a, int b) {
    return a - b;
}

int multiply(int a, int b) {
    return a * b;
}

int divide(int a, int b) {
    return a / b;
}

int (*operations[4])(int, int) = {add, subtract, multiply, divide};

int main() {
    int choice;
    int a, b;
    int res;
    
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Choose an operator to use:\n");
    printf("\t1: Add\n");
    printf("\t2: Subtract\n");
    printf("\t3: Multiply\n");
    printf("\t4: Divide\n");
    printf("Enter your choice: ");
    scanf("%d", &choice);

    printf("Enter two integers:\n");
    scanf("%d %d", &a, &b);

    res = (*operations[choice-1])(a, b);
    
    printf("%d\n", res);
    return 0;
}