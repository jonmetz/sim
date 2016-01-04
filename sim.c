#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <stdint.h>
#include <stdbool.h>

/* #include "mmio.h" */

// general stuff
enum {
  /* Sizes */

  NUMREGS = 17,
  MEMSIZE = 65535,
  UNPREDICTABLE = 153, /* 1001 1001 */
  CLEAR = 0xFFFF,

  /* Registers */
  PC = 15,
  STATUS = 16,

  /* Flags */
  N = 3,
  Z = 2,
  C = 1,
  V = 0,

  /* Memory Mapped IO regions */
  KEYBOARD_ADDR = 0xb000,
  MONI_START_ADDR = 0xc000,
  MONI_END_ADDR = 0xffff
};

/* Formats */
typedef enum _Format {
  FMT_0,
  FMT_3,
  FMT_4,
  FMT_5,
  FMT_9,
  FMT_12,
  FMT_16,
  UNKOWN_FORMAT
} Format;

/* Instruction Types */
typedef enum _Instr_Type {
  ADD1,
  ADD2,
  AND,
  ASR,
  B,
  CMP1,
  CMP2,
  CMP3,
  EOR,
  HALT,
  LDR,
  LDRB,
  MOV1,
  MOV2,
  NEG,
  STR,
  STRB,
  TST,
  UNKNOWN_TYPE
} Instr_Type;

/* Conditions */
typedef enum _Condition {
  EQ,
  NE,
  CS,
  CC,
  MI,
  PL,
  VS,
  VC,
  HI,
  LS,
  GE,
  LT,
  GT,
  LE,
  UNKNOWN_COND
} Condition;

/* Instruction */
typedef struct _Instruction {
  uint8_t low, high;
  Format format;
  Instr_Type itype;
  uint8_t rs, rd, rb; /* Indices of registers */
  uint8_t imm5, imm8;
  Condition cond;
} Instruction;


/* Prototypes */

/* Bit manipulation */
uint8_t test_bit(uint8_t byte, int bit);
// Pre-condition: 0 <= bit < 8
uint8_t btoi(uint8_t byte, int start, int end);
// Pre-condition: 0 <= end < start < 8

/* Flag functions */
void set_flag(uint32_t *status, uint8_t flag, uint8_t value);
void set_v_flag(uint32_t *status, uint8_t op1_sign, uint8_t op2_sign, uint8_t sum_sign);

/* Register Indices functions */
bool is_valid_reg(uint8_t reg);
bool is_low_reg(uint8_t reg);
bool is_high_reg(uint8_t reg);

/* Instruction functions */
void get_instructions(char *filename, uint8_t *buffer);
void set_format(Instruction *instr);
void set_itype(Instruction *instr);
void set_operands(Instruction *instr);

/* Instruction Type functions */
void add1(Instruction *instr, uint32_t *regs);
void add2(Instruction *instr, uint32_t *regs);
void and(Instruction *instr, uint32_t *regs);
void asr(Instruction *instr, uint32_t *regs);
bool is_cond_true(Condition cond, uint32_t status);
void b(Instruction *instr, uint32_t *regs);
void set_cmp_flags(uint32_t *status, uint32_t alu_out);
void cmp1(Instruction *instr, uint32_t *regs);
void cmp2(Instruction *instr, uint32_t *regs);
void cmp3(Instruction *instr, uint32_t *regs);
void eor(Instruction *instr, uint32_t *regs);
void halt(uint32_t *regs);
void ldr(Instruction *instr, uint32_t *regs, uint8_t *memory);
void ldrb(Instruction *instr, uint32_t *regs, uint8_t *memory);
void mov1(Instruction *instr, uint32_t *regs);
void mov2(Instruction *instr, uint32_t *regs);
void neg(Instruction *instr, uint32_t *regs);
void str(Instruction *instr, uint32_t *regs, uint8_t *memory);
void strb(Instruction *instr, uint32_t *regs, uint8_t *memory);
void tst(Instruction *instr, uint32_t *regs);


int main(int argc, char *argv[]) {
  uint32_t GeneralRegs[NUMREGS] = {0};
  uint8_t Memory[MEMSIZE] = {0};
  Instruction instr;
  int i;

  get_instructions(argv[1], Memory);
  GeneralRegs[PC] = 0;

  while (1) {
    instr.low = Memory[GeneralRegs[PC]];
    instr.high = Memory[GeneralRegs[PC] + 1];
    set_format(&instr);
    set_itype(&instr);
    set_operands(&instr);
    switch(instr.itype) {
    case ADD1:
      add1(&instr, GeneralRegs);
      break;
    case ADD2:
      add2(&instr, GeneralRegs);
      break;
    case AND:
      and(&instr, GeneralRegs);
      break;
    case ASR:
      asr(&instr, GeneralRegs);
      break;
    case B:
      b(&instr, GeneralRegs);
      break;
    case CMP1:
      cmp1(&instr, GeneralRegs);
      break;
    case CMP2:
      cmp2(&instr, GeneralRegs);
      break;
    case CMP3:
      cmp3(&instr, GeneralRegs);
      break;
    case EOR:
      eor(&instr, GeneralRegs);
      break;
    case HALT:
      halt(GeneralRegs); // should never return
      assert(NULL && "impossible state reached");
    case LDR:
      ldr(&instr, GeneralRegs, Memory);
      break;
    case LDRB:
      ldrb(&instr, GeneralRegs, Memory);
      break;
    case MOV1:
      mov1(&instr, GeneralRegs);
      break;
    case MOV2:
      mov2(&instr, GeneralRegs);
      break;
    case NEG:
      neg(&instr, GeneralRegs);
      break;
    case STR:
      str(&instr, GeneralRegs, Memory);
      break;
    case STRB:
      strb(&instr, GeneralRegs, Memory);
      break;
    case TST:
      tst(&instr, GeneralRegs);
      break;
    default:
      fprintf(stderr, "Illegal instruction type...");
      exit(EXIT_FAILURE);
    }

    // If the instruction wasn't a branch
    if (instr.itype != B)
      // Increment the PC
      GeneralRegs[PC] += 2;

    // ensure that we don't read from keyboard or mouse's memory
    assert(GeneralRegs[PC] != KEYBOARD_ADDR && "trying to execute instructions from memory mapped IO region (keyboard)");
    assert(!((MONI_START_ADDR <= GeneralRegs[PC]) && (GeneralRegs[PC] <= MONI_END_ADDR)) &&
	   "trying to execute instructions from memory mapped IO region (monitor)");

  }

  return 0;
}

/****************************************************************
Bit manipulation
 ****************************************************************/

/*
 * Tests the bit from the byte at the location bit
 * Returns 1 if the bit is 1, 0 otherwise
 */
uint8_t test_bit(uint8_t byte, int bit) {
  return (byte & (1 << bit)) != 0;
}

/*
 * Binary to unsigned integer: gets the decimal value from the bits
 * [start:end] from byte.
 */
uint8_t btoi(uint8_t byte, int start, int end) {
  uint8_t decimal = 0;
  int i;

  for (i = start; i >= end; i--) {
    decimal = (2 * decimal) + test_bit(byte, i);
  }

  return decimal;
}



/****************************************************************
 Flag functions
 ****************************************************************/

/*
 * Sets the value for the specific flag in the status register
 */
void set_flag(uint32_t *status, uint8_t flag, uint8_t value) {
  // incorrect flag location
  if (flag > 3) {
    fprintf(stderr, "Incorrect flag location...");
    exit(EXIT_FAILURE);
  }

  // check if the flag has the correct value
  uint8_t v = test_bit((uint8_t) *status, flag);
  // if the flag does not have the correct value
  if (v != value)
    // toggle the bit
    *status ^= (1 << flag);
}

/*
 * Assume addition.
 * Sets the V flag based on the sign bits of the two operands and the sum
 */
void set_v_flag(uint32_t *status, uint8_t op1_sign, uint8_t op2_sign, uint8_t sum_sign) {
  // if both operands are positive but the sum is negative, then overflow
  if (op1_sign == op2_sign && op1_sign == 0 && sum_sign == 1)
    set_flag(status, V, 1);
  // if both operands are negative but the sum is positive, then overflow
  else if (op1_sign == op2_sign && op1_sign == 1 && sum_sign == 0)
    set_flag(status, V, 1);
  // Otherwise, no overflow can occur if the operands are opposite sign
  else set_flag(status, V, 0);
}


/****************************************************************
 Register Indices functions
 ****************************************************************/

/*
 * Checks to see if the register index given is valid (between 0 and 15)
 */
bool is_valid_reg(uint8_t reg_index) {
  if (reg_index <= 15)
    return true;
  else
    return false;
}

/*
 * Checks to see if the register index given corresponds to a low register
 */
bool is_low_reg(uint8_t reg_index) {
  if (reg_index <= 7)
    return true;
  else
    return false;
}

/*
 * Checks to see if the register index given corresponds to a high register
 */
bool is_high_reg(uint8_t reg_index) {
  if (reg_index >= 8 && reg_index <= 14)
    return true;
  else
    return false;
}



/****************************************************************
 Instruction functions
 ****************************************************************/

/*
 * Gets instructions from a file and stores each byte into the buffer.
 * Storage is little-endian.
 */
void get_instructions(char *filename, uint8_t *buffer) {
  // Open the binary file for reading
  FILE *fp = fopen(filename, "rb");

  // Could not open the file
  if (fp == NULL) {
    fprintf(stderr, "Could not open the binary file %s...", filename);
    exit(EXIT_FAILURE);
  }

  // Read and store one byte at a time
  while (!feof(fp)) {
    fread(buffer++, 1, 1, fp);
  }

  // Close the file
  fclose(fp);
}

/*
 * Sets the format of the instruction by looking at bits [15:13] so [7:5]h
 */
void set_format(Instruction *instr) {
  // Instruction format is set by looking at bits [15:13] so [7:5]h
  // 0 -> FMT_0
  // 1 -> FMT_3
  // 2 -> FMT_4 or FMT_5
  // 3 -> FMT_9
  // 5 -> FMT_12
  // 6 -> FMT_16
  uint8_t format = btoi(instr->high, 7, 5);
  Format f = UNKOWN_FORMAT;

  // Distinguish between format 4 and 5 by looking at bits [12:10]
  // so bits [4:2]h
  if (format == 2) {
    format = btoi(instr->high, 4, 2);
    if (format == 0)
      f = FMT_4;
    else if (format == 1)
      f = FMT_5;
  }
  else if (format == 0)
    f = FMT_0;
  else if (format == 1)
    f = FMT_3;
  else if (format == 3)
    f = FMT_9;
  else if (format == 5)
    f = FMT_12;
  else if (format == 6)
    f = FMT_16;

  instr->format = f;
}

/*
 * Sets the instruction type from the format of the instruction given
 */
void set_itype(Instruction *instr) {
  Format format = instr->format;
  Instr_Type type = UNKNOWN_TYPE;

  // Format 0
  if (format == FMT_0) {
    // HALT occurs when low == high == 0
    if (instr->high == 0 && instr->low == 0)
      type = HALT;
  }

  // Format 3
  else if (format == FMT_3) {
    // Determine OP by looking at bits [12:11] so bits [4:3]h
    // OP = 0 -> MOV1
    // OP = 1 -> CMP1
    uint8_t OP = btoi(instr->high, 4, 3);
    if (OP == 0)
      type = MOV1;
    else if (OP == 1)
      type = CMP1;
  }

  // Format 4
  else if (format == FMT_4) {
    // Determine OP by looking at bits [9:6]
    // OP = [9:8] * 4 + [7:6] => OP = [1:0]h * 4 + [7:6]l
    // 0 -> AND
    // 1 -> EOR
    // 2 -> ASR
    // 3 -> TST
    // 4 -> NEG
    // 5 -> CMP2
    uint8_t OP = btoi(instr->high, 1, 0) * 4 + btoi(instr->low, 7, 6);
    if (OP == 0)
      type = AND;
    else if (OP == 1)
      type = EOR;
    else if (OP == 2)
      type = ASR;
    else if (OP == 3)
      type = TST;
    else if (OP == 4)
      type = NEG;
    else if (OP == 5)
      type = CMP2;
  }

  // Format 5
  else if (format == FMT_5) {
    // Determine OP by looking at bits [9:8] or [1:0]h
    // 0 -> ADD1
    // 1 -> CMP3
    // 2 -> MOV2
    uint8_t OP = btoi(instr->high, 1, 0);
    if (OP == 0)
      type = ADD1;
    else if (OP == 1)
      type = CMP3;
    else if (OP == 2)
      type = MOV2;
  }

  // Format 9
  else if (format == FMT_9) {
    // B is 4th bit of high and L is 3rd bit of high
    // B == L == 0 -> STR
    // B == 0 && L == 1 -> LDR
    // B == 1 && L == 0 -> STRB
    // B == L == 1 -> LDRB
    uint8_t B = test_bit(instr->high, 4);
    uint8_t L = test_bit(instr->high, 3);
    if (B == 0 && L == 0)
      type = STR;
    else if (B == 0 && L == 1)
      type = LDR;
    else if (B == 1 && L == 0)
      type = STRB;
    else
      type = LDRB;
  }

  // Format 12
  else if (format == FMT_12) {
    // SP is 3rd bit of high
    // SP == 0 -> ADD2
    uint8_t SP = test_bit(instr->high, 3);
    if (SP == 0)
      type = ADD2;
  }

  // Format 16
  else if (format == FMT_16) {
    // B instruction type
    type = B;
  }

  // set the instruction type in the instruction
  instr->itype = type;
}

/*
 * Sets the operands based on the instruction format
 */
void set_operands(Instruction *instr) {
  Format format = instr->format;

  // Format 3
  if (format == FMT_3) {
    // Rd is [2:0]h and Immediate8 is low
    instr->rd = btoi(instr->high, 2, 0);
    instr->imm8 = instr->low;
  }

  // Format 4 or Format 5
  else if (format == FMT_4 || format == FMT_5) {
    // Rs is [5:3]l and Rd is [2:0]l
    instr->rs = btoi(instr->low, 5, 3);
    instr->rd = btoi(instr->low, 2, 0);
    // Rs and Rd differ for format 5
    if (format == FMT_5) {
      // get 3rd bit of Rs from the 6th bit of low
      //                Rd from the 7th bit of low
      instr->rs += (test_bit(instr->low, 6) * 8);
      instr->rd += (test_bit(instr->low, 7) * 8);
    }
  }

  // Format 9
  else if (format == FMT_9) {
    // Imm5 is bits [9:6]
    // Imm5 = [2:0]h * 4 + [7:6]l
    // Rb is [5:3]l and Rd is [2:0]l
    instr->imm5 = btoi(instr->high, 2, 0) * 4 + btoi(instr->low, 7, 6);
    instr->rb = btoi(instr->low, 5, 3);
    instr->rd = btoi(instr->low, 2, 0);
  }

  // Format 12
  else if (format == FMT_12) {
    // Rd is bits [2:0]h and Imm8 is low
    instr->rd = btoi(instr->high, 2, 0);
    instr->imm8 = instr->low;
  }

  // Format 16
  else if (format == FMT_16) {
    // Cond is bits [3:0]h and branch offset will be set as imm8 = low
    // 0 -> EQ  1 -> NE  2 -> CS  3 -> CC
    // 4 -> MI  5 -> PL  6 -> VS  7 -> VC
    // 8 -> HI  9 -> LS  10-> GE  11-> LT
    // 12-> GT  13-> LE
    instr->imm8 = instr->low;
    uint8_t condition = btoi(instr->high, 3, 0);
    if (condition > 13)
      instr->cond = (Condition) 14;
    else
      instr->cond = (Condition) condition;
  }
}



/****************************************************************
Instruction Type functions
****************************************************************/

/* Add Rd, Rs */
void add1(Instruction *instr, uint32_t *regs) {
  // Rd must be a valid reg
  if (!is_valid_reg(instr->rd)) {
    fprintf(stderr, "Rd must be a valid register for ADD1...");
    exit(EXIT_FAILURE);
  }

  // Get sign of Rd before addition
  uint8_t rd_sign = (regs[instr->rd] & (1 << 15)) != 0;
  uint8_t rs_sign = (regs[instr->rs] & (1 << 15)) != 0;

  // Rd = Rd + Rs
  regs[instr->rd] += regs[instr->rs];

  // N flag = Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);

  // C flag = if (carry out) then 1 else 0
  uint8_t carry = (regs[instr->rd] & (1 << 16)) != 0;
  set_flag(&regs[STATUS], C, carry);

  // V flag = if (signed overflow) then 1 else 0
  set_v_flag(&regs[STATUS], rd_sign, rs_sign, rd15);

  // Clear upper 16 bits of Rd
  regs[instr->rd] = regs[instr->rd] & CLEAR;
}

/* Add Rd, PC, Imm8<<2 */
void add2(Instruction *instr, uint32_t *regs) {
  // Rd must be a low register
  if (!is_low_reg(instr->rd)) {
    fprintf(stderr, "Rd must be a low register for ADD2...");
    exit(EXIT_FAILURE);
  }

  // Rd = (PC AND 0xFFFC) + (Immediate8 << 2)
  uint16_t offset = instr->imm8 << 2;
  regs[instr->rd] = (regs[PC] & 0xFFFC) + offset;

  // Clear upper 16 bits of Rd
  regs[instr->rd] = regs[instr->rd] & CLEAR;
}

/* And Rd, Rs */
void and(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rs must be low regs for AND...");
    exit(EXIT_FAILURE);
  }

  // Rd = (Rd and Rs)
  regs[instr->rd] = regs[instr->rd] & regs[instr->rs];

  // N flag = Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}

/* Asr Rd, Rs */
void asr(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rs must be low regs for ASR...");
    exit(EXIT_FAILURE);
  }

  // Store low 8-bits of Rs: Rs[7:0]
  uint8_t low_rs = (uint8_t) regs[instr->rs];

  // Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;

  if (low_rs < 16 && low_rs != 0) {
    // C flag = Rd[Rs[7:0] - 1]
    // Rd = Rd >> Rs[7:0]
    uint8_t c_val = (regs[instr->rd] & (1 << (low_rs - 1))) != 0;
    set_flag(&regs[STATUS], C, c_val);
    regs[instr->rd] = regs[instr->rd] >> low_rs;
  }
  else if (low_rs >= 16) {
    // C flag = Rd[15]
    set_flag(&regs[STATUS], C, rd15);
    regs[instr->rd] = rd15 == 0 ? 0 : 0xFFFF;
  }

  // N flag = Rd[15]
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}

/*
 * Checks to see if the condition for the branch instruction is true
 */
bool is_cond_true(Condition cond, uint32_t status) {
  // Get the bit values for all the flags
  uint8_t n = test_bit((uint8_t) status, N);
  uint8_t z = test_bit((uint8_t) status, Z);
  uint8_t c = test_bit((uint8_t) status, C);
  uint8_t v = test_bit((uint8_t) status, V);

  if (cond == EQ) {
    return z == 1 ? true : false;
  }
  else if (cond == NE) {
    return z == 0 ? true : false;
  }
  else if (cond == CS) {
    return c == 1 ? true : false;
  }
  else if (cond == CC) {
    return c == 0 ? true : false;
  }
  else if (cond == MI) {
    return n == 1 ? true : false;
  }
  else if (cond == PL) {
    return n == 0 ? true : false;
  }
  else if (cond == VS) {
    return v == 1 ? true : false;
  }
  else if (cond == VC) {
    return v == 0 ? true : false;
  }
  else if (cond == HI) {
    return ((c == 1) && (z == 0)) ? true : false;
  }
  else if (cond == LS) {
    return ((c == 0) || (z == 1)) ? true : false;
  }
  else if (cond == GE) {
    return n == v ? true : false;
  }
  else if (cond == LT) {
    return n != v ? true : false;
  }
  else if (cond == GT) {
    return ((z == 0) && (n == v)) ? true : false;
  }
  else if (cond == LE) {
    return ((z == 1) || (n != v)) ? true : false;
  }

  return false;
}

/* B(cond) target_address */
void b(Instruction *instr, uint32_t *regs) {
  // If not a correct condition
  if (instr->cond == UNKNOWN_COND) {
    fprintf(stderr, "Unknown condition for B...");
    exit(EXIT_FAILURE);
  }

  // Check to see if the condition is true
  if (is_cond_true(instr->cond, regs[STATUS])) {
    // Left shift offset by 1
    instr->imm8 = instr->imm8 << 1;

    // Sign extend offset to 16 bits
    int8_t signed_offset = instr->imm8;
    int16_t extended_offset = signed_offset;

    // Add the extended offset to the PC
    regs[PC] += extended_offset;
  }
  else {
    // Increment the PC in a regular way
    regs[PC] += 2;
  }

  // Clear upper 16 bits of PC
  regs[PC] = regs[PC] & CLEAR;
}

/* Set the N, Z, and C flags for the CMP* instructions */
void set_cmp_flags(uint32_t *status, uint32_t alu_out) {
  // N flag = alu_out[15]
  uint8_t alu15 = (alu_out & (1 << 15)) != 0;
  set_flag(status, N, alu15);

  // Z flag = if (alu_out == 0) then 1 else 0
  ((uint16_t) alu_out) == 0 ? set_flag(status, Z, 1) : set_flag(status, Z, 0);

  // C flag = if (borrow from last bit) then 0 else 1
  uint8_t alu16 = (alu_out & (1 << 16)) != 0;
  set_flag(status, C, alu16);
}

/* Cmp Rd, #Immediate8 */
void cmp1(Instruction *instr, uint32_t *regs) {
  // Rd must be a low register
  if (!is_low_reg(instr->rd)) {
    fprintf(stderr, "Rd must be a low reg for CMP1...");
    exit(EXIT_FAILURE);
  }

  // alu_out = Rd - Immediate8
  uint32_t alu_out = regs[instr->rd] + (uint16_t) (~instr->imm8) + 1;

  // Get Rd sign bit
  uint8_t rd_sign = (regs[instr->rd] & (1 << 15)) != 0;

  // Update the N, Z, and C flags
  set_cmp_flags(&regs[STATUS], alu_out);

  // V flag = if (signed overflow) then 1 else 0
  // Sign of immediate will always be 1
  uint8_t alu_sign = (alu_out & (1 << 15)) != 0;
  set_v_flag(&regs[STATUS], rd_sign, 1, alu_sign);
}

/* Cmp Rd, Rs (low) */
void cmp2(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rs must be low regs for CMP2...");
    exit(EXIT_FAILURE);
  }

  // alu_out = Rd - Rs
  uint32_t alu_out = regs[instr->rd] + (uint16_t) (~regs[instr->rs]) + 1;

  // Get Rd sign bit
  uint8_t rd_sign = (regs[instr->rd] & (1 << 15)) != 0;

  // Update the N, Z, and C flags
  set_cmp_flags(&regs[STATUS], alu_out);

  // V flag = if (signed overflow) then 1 else 0
  uint8_t rs_sign = !((regs[instr->rs] & (1 << 15)) != 0);
  uint8_t alu_sign = (alu_out & (1 << 15)) != 0;
  set_v_flag(&regs[STATUS], rd_sign, rs_sign, alu_sign);
}

/* Cmp Rd, Rs (any) */
void cmp3(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be valid registers
  if (!is_valid_reg(instr->rd) || !is_valid_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rs must be valid regs for CMP3...");
    exit(EXIT_FAILURE);
  }

  // alu_out = Rd - Rs
  uint32_t alu_out = regs[instr->rd] + (uint16_t) (~regs[instr->rs]) + 1;

  // Get Rd sign bit
  uint8_t rd_sign = (regs[instr->rd] & (1 << 15)) != 0;

  // Update the N, Z, and C flags
  set_cmp_flags(&regs[STATUS], alu_out);

  // V flag = if (signed overflow) then 1 else 0
  uint8_t rs_sign = !((regs[instr->rs] & (1 << 15)) != 0);
  uint8_t alu_sign = (alu_out & (1 << 15)) != 0;
  set_v_flag(&regs[STATUS], rd_sign, rs_sign, alu_sign);
}

/* Eor Rd, Rs */
void eor(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rs must be low regs for EOR...");
    exit(EXIT_FAILURE);
  }

  // Rd = (Rd EOR Rs)
  regs[instr->rd] = regs[instr->rd] ^ regs[instr->rs];

  // N flag = Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}

/* Halt */
void halt(uint32_t *regs) {
  int i;
  // print the registers
  printf("Low Registers:\n");
  for (i = 0; i < 8; i++)
    printf("r%d = %d\n", i, (uint16_t) regs[i]);
  printf("High Registers:\n");
  for (i = 8; i < 15; i++)
    printf("r%d = %d\n", i, (uint16_t) regs[i]);
  printf("Program Counter:\n");
  printf("PC = %d\n", (uint16_t) regs[PC]);
  printf("Flags:\n");
  printf("N Z C V\n");
  uint8_t n = test_bit((uint8_t) regs[STATUS], N);
  uint8_t z = test_bit((uint8_t) regs[STATUS], Z);
  uint8_t c = test_bit((uint8_t) regs[STATUS], C);
  uint8_t v = test_bit((uint8_t) regs[STATUS], V);
  printf("%d %d %d %d\n", n, z, c, v);

  // Exit the program successfully
  exit(0);
}

/* Ldr Rd, [ Rb, #Imm5 <<2 ] */
void ldr(Instruction *instr, uint32_t *regs, uint8_t *memory) {
  // Rd and Rb must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rb)) {
    fprintf(stderr, "Rd and Rb must be low regs for LDR...");
    exit(EXIT_FAILURE);
  }

  uint16_t data;

  // address = Rb + (Imm5 << 2)
  uint16_t address = ((uint16_t) regs[instr->rb]) + (instr->imm5 << 2);

  // read from keyboard
  /* if (address == KEYBOARD_ADDR){ */
  /*   data = Read_Keyboard(); */
  /* } */
  // if address is divisible by 4
  if (address % 4 == 0){
    // data = Memory[address+1] , Memory[address]
    data = (memory[address+1] << 8) + memory[address];
  }
  else {
    data = UNPREDICTABLE;
  }

  // Rd = data
  regs[instr->rd] = data;
}

/* Ldrb Rd, [ Rb, #Imm5 ] */
void ldrb(Instruction *instr, uint32_t *regs, uint8_t *memory) {
  // Rd and Rb must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rb)) {
    fprintf(stderr, "Rd and Rb must be low regs for LDRB...");
    exit(EXIT_FAILURE);
  }

  // address = Rb + (Imm5)
  uint16_t address = ((uint16_t) regs[instr->rb]) + instr->imm5;

  // read from keyboard
  /* if (address == 0xb000){ */
  /*   /\* regs[instr->rd] = Read_Keyboard(); *\/ */
  /* } */
  // Rd = Memory[address]
  /* else { */
    regs[instr->rd] = memory[address];
  /* } */
}

/* Mov Rd, #Immediate8 */
void mov1(Instruction *instr, uint32_t *regs) {
  // Rd must be a low register
  if (!is_low_reg(instr->rd)) {
    fprintf(stderr, "Rd must be a low reg for MOV1...");
    exit(EXIT_FAILURE);
  }

  // printf("Imm8 = %d\n", instr->imm8);

  // Rd = Immediate8
  regs[instr->rd] = instr->imm8;

  // N flag = 0
  set_flag(&regs[STATUS], N, 0);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}

/* Mov Rd, Rs */
void mov2(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_valid_reg(instr->rd) || !is_valid_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rb must be low regs for MOV2...");
    exit(EXIT_FAILURE);
  }

  // Rd = Rs
  regs[instr->rd] = regs[instr->rs];

  // N flag = Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}

/* Neg Rd, Rs */
void neg(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rb must be low regs for NEG...");
    exit(EXIT_FAILURE);
  }

  // Get sign bit of rd
  uint8_t rd_sign = (regs[instr->rd] & (1 << 15)) != 0;

  // Rd = 0 - Rs
  regs[instr->rd] = 0 + (uint16_t) (~regs[instr->rs]) + 1;

  // N flag = Rd[15]
  uint8_t rd15 = (regs[instr->rd] & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, rd15);

  // Z flag = if (Rd == 0) then 1 else 0
  ((uint16_t) regs[instr->rd]) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);

  // C flag = if (borrowed from last bit) then 0 else 1
  uint8_t rd16 = (regs[instr->rd] & (1 << 16)) != 0;
  set_flag(&regs[STATUS], C, rd16);

  // V flag = if (signed overflow) then 1 else 0
  set_v_flag(&regs[STATUS], 0, !rd_sign, rd15);

  // Clear upper 16 bits of Rd
  regs[instr->rd] = regs[instr->rd] & CLEAR;
}

void str(Instruction *instr, uint32_t *regs, uint8_t *memory) {
  uint16_t address = ((uint16_t) regs[instr->rb]) + (instr->imm5 << 2);
  if (address % 4 == 0) {
    // Memory[address+1]= Rd[15:8]
    memory[address+1] = (uint8_t) (regs[instr->rd] >> 8);
    // Memory[address] = Rd[7:0]
    memory[address] = (uint8_t) regs[instr->rd];
  }
  else {
    memory[address+1] = UNPREDICTABLE;
    memory[address] = UNPREDICTABLE;
  }
}

/* Strb Rd, [ Rb, #Imm5 ] */
void strb(Instruction *instr, uint32_t *regs, uint8_t *memory) {
  // Rd and Rb must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rb)) {
    fprintf(stderr, "Rd and Rb must be low regs for STRB...");
    exit(EXIT_FAILURE);
  }

  // address = Rb + (Imm5)
  uint16_t address = ((uint16_t) regs[instr->rb]) + instr->imm5;

  // Memory[address] = Rd[7:0]
  memory[address] = (uint8_t) regs[instr->rd];
}

/* Tst Rd, Rs */
void tst(Instruction *instr, uint32_t *regs) {
  // Rd and Rs must be low registers
  if (!is_low_reg(instr->rd) || !is_low_reg(instr->rs)) {
    fprintf(stderr, "Rd and Rb must be low regs for TST...");
    exit(EXIT_FAILURE);
  }

  // alu_out = (Rd and Rs)
  uint32_t alu_out = regs[instr->rd] & regs[instr->rs];

  // N flag = alu_out[15]
  uint8_t alu15 = (alu_out & (1 << 15)) != 0;
  set_flag(&regs[STATUS], N, alu15);

  // Z flag = if (alu_out == 0) then 1 else 0
  ((uint16_t) alu_out) == 0 ? set_flag(&regs[STATUS], Z, 1) : set_flag(&regs[STATUS], Z, 0);
}
