#include "instruction.h"
#include "macros.h"

Instruction::Instruction()
{
  length = 0;
  vex1.encoded = 0;
  modRM.encoded = 0;
  patch = 0;
  prologueSize = 0;
}

void Instruction::clear()
{
  length = 0;
  vex1.encoded = 0;
  modRM.encoded = 0;
  patch = 0;
  prologueSize = 0;  
}

// returns possible patches
unsigned Instruction::getPatch(void)
{
  return patch;
}

// Takes a pointer to the begin of the instructions.
// n is sum of previous instruction's the lengts. It is needed to make correct
// patches for instructions that are relative to the instruction pointer
// If 0 length returned the instruction couldn't be decoded or can not be moved.
int Instruction::decodeInstruction(const void *sym, int n)
{
  prologueSize = n;
  unsigned char *insns = (unsigned char *) sym;
  int prefixes = decodePrefix(insns);
  insns += prefixes;  
  decodeOpcode(insns);
  return length;
}

// Check possible instruction prefixes. Marks the prefix set and adds the
// instruction length by one or in some cases by 5 if prefix is found and moves
// to next index of the insns.
int Instruction::decodePrefix(unsigned char *insns)
{
  int prefixes = 0;
  char done = 0;
  do
  {
    switch (*insns)
    {
      case 0xf0:
      case 0xf2:
      case 0xf3:
      case 0x2e:
      case 0x36:
      case 0x3e:
      case 0x26:
      case 0x66:
      case 0x67:
        prefixes++;
        length++;
        insns++;
        break;
      case 0x64:
      case 0x65:
        prefixes++;
        length += 5;
        insns++;
        break;
      default:
        done = 1;
    }
  } while (!done);

  // REX prefix is always the last prefix
  if ((*insns & 0xf0) == 0x40)
  {
    prefixes++;
    length++;
  }
  return prefixes;
}

// Decodes the length of the instruction after prefixes.
// First the function check which opcode lookup table entry (map) need to be
// used. After the map selection, the opcode group is read from the map and
// instruction length is decoded.
void Instruction::decodeOpcode(unsigned char *insns)
{
  // Check select correct opcode map
  int select_map;
  switch (*insns)
  {
    case 0xf8:  // Pop Ev or XOP
      modRM.encoded = insns[1];
      if (modRM.bits.reg == 0)
      {
        evalModRM(insns[1]);
        return;
      }
      else  // FIXME add support for XOP
        length = 0;
        return;
    case 0xc4:  // 3 byte vex encoded
      vex1.encoded = insns[1];
      if (vex1.bits.map == 1)
        select_map = 1;
      else if (vex1.bits.map == 2)
        select_map = 2;
      else
        select_map = 3;
      length += 3;
      insns += 3;
      break;
    case 0x0f:
      if (insns[1] == 0x38) // 3 byte opcode
      {
        select_map = 2;
        length += 2;
        insns += 2;
      }
      else if (insns[1] == 0x3a) // 3 byte opcode
      {
        select_map = 3;
        length += 2;
        insns += 2;
      }
      else  // 2 byte opcode
      {
        select_map = 1;
        length++;
        insns++;
      }
      break;
    case 0xc5:  // 2 byte vex encoded. (map b00001)
      select_map = 1;
      length += 2;
      insns += 2;
      break;
    default:
      select_map = 0;
  }

  int group = ins_lookup[select_map][*insns];
  switch (group)
  {
    case 0:
      length += 1;
      break;
    case 1:
      length += 2;
      break;
    case 2:
      length += 5;
      break;
    case 3:
      evalModRM(insns[1]);
      break;
    case 4:
      length += 1;
      evalModRM(insns[1]);
      break;
    case 5:
      length += 4;
      evalModRM(insns[1]);
      break;
    case 6: //invalid
      length = 0;
      break;
    case 7:
      groupF6F7(insns);
      break;
    case 8:
      length += 8;
      evalModRM(insns[1]);
      break;
    case 9: // jmp 4byte off (need patch)
      length += 5;
      makePatch();
      break;
    case 10:
      groupFF(insns);
      break;
    case 11:
      group0F00(insns);
      break;
    case 12:
      group3dNOW(insns);
      break;
    case 13:
      groupSSE5A(insns);
      break;
  }
}

// Handles opcode groups 0xF6 and 0xF7
void Instruction::groupF6F7(unsigned char *insns)
{
  modRM.encoded = insns[1];
  if (modRM.bits.reg == 0 || modRM.bits.reg == 1)
  {
    if (*insns == 0xf6)
      length += 1;
    else
      length += 4;
  }
  evalModRM(insns[1]);
}

// Handles opcode group 0xFF
void Instruction::groupFF(unsigned char *insns)
{
  modRM.encoded = insns[1];
  if (modRM.bits.reg == 0 || modRM.bits.reg == 1
      || modRM.bits.reg == 6)
    evalModRM(insns[1]);
  else
    length = 0;
}

//Handles opcode group 0x0F 0x00
void Instruction::group0F00(unsigned char *insns)
{
  modRM.encoded = insns[1];
  if (modRM.bits.reg != 6)
    evalModRM(insns[1]);
  else
    length = 0;
}

// AMD old 3dNOW! instructions. Returns 0 as they are not
// yet supported 
void Instruction::group3dNOW(unsigned char *insns UNUSED)
{
  length = 0; //not yet supported
}

void Instruction::groupSSE5A(unsigned char *insns UNUSED)
{
  length = 0; //not yet supported
}

// Decode modRM byte and adds correct length and calls makepatch if needed
void Instruction::evalModRM(unsigned char insns)
{
  modRM.encoded = insns;
  //mod == 00 and rm == 5 opcode, modRM, rip + 32bit
  //mod == 00 opcode, modRM,(SIB)
  //mod == 01 opcode,modRM,(SIB),1 byte immediate
  //mod == 10 opcode,modRM,(SIB),4 byte immeadiate
  //mod == 11 opcode,modRM
  if (modRM.bits.mod == 0 && modRM.bits.rm == 5)
    makePatch();
  else if (modRM.bits.mod == 0)
    (modRM.bits.rm) != 4 ? length += 2 : length += 3;  //check if SIB byte is needed
  else if (modRM.bits.mod == 1)
    (modRM.bits.rm) != 4 ? length += 3 : length += 4;  //check if SIB byte is needed
  else if (modRM.bits.mod == 2)
    (modRM.bits.rm) != 4 ? length += 6 : length += 7;  //check if SIB byte is needed
  else
    length += 2;
}

// Creates patch for position relative instructions to allow relocating it.
void Instruction::makePatch()
{
  int n = prologueSize + length;
  int extra = modRM.encoded ? 1 : 0;
  patch = (n+0x5 + extra)*0x100 + n + 1 + extra;
  length += 5 + extra; 
}
