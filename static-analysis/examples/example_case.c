/* 검산용 가짜 케이스(Juliet 구조를 흉내 냄, 실제 Juliet 코드 아님) */
#include "std_testcase.h"
#ifndef OMITBAD
void EX476_example_01_bad()
{
    int * data = NULL;
    printIntLine(*data);
}
#endif /* OMITBAD */
#ifndef OMITGOOD
static void goodG2B()
{
    char dest[10];
    strcpy(dest, "ok");
    printLine(dest);
}
#endif /* OMITGOOD */
#ifdef INCLUDEMAIN
int main(int argc, char * argv[])
{
#ifndef OMITBAD
    EX476_example_01_bad();
#endif /* OMITBAD */
    return 0;
}
#endif
