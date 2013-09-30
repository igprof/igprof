/* Prorgam: test_user_ccnt
 * CMake tries to run this program to determine if CPU cycles can be read on arm
 * machines. */
int main()
{
  unsigned v;
  __asm__ volatile ("MRC p15, 0, %0, c9, c13, 0\t\n": "=r"(v));
  return v;
}
