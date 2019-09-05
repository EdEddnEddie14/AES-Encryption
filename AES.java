import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Scanner;

public class AES {
	
	// fixed substitution box used for subBytes operation of encryption algorithm
	public static final int[][] S_BOX =
		{{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
		{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
		{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
		{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
		{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
		{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
		{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
		{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
		{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
		{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
		{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
		{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
		{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
		{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
		{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
		{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}};
	
	// fixed inverse of above subtitution box used for invSubBytes operation of decryption algorithm
	public static final int[][] INV_S_BOX = 
		{{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
		{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
		{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
		{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
		{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
		{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
		{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
		{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
		{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
		{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
		{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
		{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
		{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
		{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
		{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
		{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}};
	
	// 
	public static final int[] LOG_TABLE =
		{0,   0,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 
		100,   4, 224,  14,  52, 141, 129, 239,  76, 113,   8, 200, 248, 105,  28, 193, 
		125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154, 201,   9, 120, 
		101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 
		150, 143, 219, 189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 
		102, 221, 253,  48, 191,   6, 139,  98, 179,  37, 226, 152,  34, 136, 145,  16, 
		126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61, 186, 
		43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 
		175,  88, 168,  80, 244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232, 
		44, 215, 117, 122, 235,  22,  11, 245,  89, 203,  95, 176, 156, 169,  81, 160, 
		127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164, 118, 123, 183, 
		204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 
		151, 178, 135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209, 
		83,  57, 132,  60,  65, 162, 109,  71,  20,  42, 158,  93,  86, 242, 211, 171, 
		68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184,  38, 119, 153, 227, 165, 
		103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7};

    public static final int[] A_LOG_TABLE =
		{1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53, 
		95, 225,  56,  72, 216, 115, 149, 164, 247,   2,   6,  10,  30,  34, 102, 170, 
		229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144, 171, 230,  49, 
		83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205, 
		76, 212, 103, 169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 
		131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206,  73, 219, 118, 154, 
		181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187, 214,  97, 163, 
		254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 
		251,  22,  58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 
		195,  94, 226,  61,  71, 201,  64, 192,  91, 237,  44, 116, 156, 191, 218, 117, 
		159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223, 122, 142, 137, 128, 
		155, 182, 193,  88, 232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84, 
		252,  31,  33,  99, 165, 244,   7,   9,  27,  45, 119, 153, 176, 203,  70, 202, 
		69, 207,  74, 222, 121, 139, 134, 145, 168, 227,  62,  66, 198,  81, 243,  14, 
		18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133, 148, 167, 242,  13,  23, 
		57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1};

    public static int[][][] roundKeys = new int[15][4][4];
	
	// 2D array used to store each line of hexadecimal input supplied by the user,
	// assumed that each line contains a String of exactly 32 hex characters (or 16 "bytes"),
	// this is where each encryption/decrpytion transformation is performed
	public static int[][] state = new int[4][4];
	
	public static void main(String[] args) throws FileNotFoundException {
		boolean encryption;
		if (args[0].toUpperCase().equals("E"))
			encryption = true;
		else if (args[0].toUpperCase().equals("D"))
			encryption = false;
		else 
			throw new IllegalArgumentException();
				
		File key = new File(args[1]);
		Scanner s = new Scanner(key);
		String initialKey = s.nextLine();
		int row = 0;
		int col = 0;
		int roundKey = 0;
		for (int byteCounter = 0; byteCounter < 64; byteCounter += 2) {
			String current = initialKey.substring(byteCounter, byteCounter + 2);
			roundKeys[roundKey][row][col] = Integer.parseInt(current, 16);
			row = (row + 1) % 4;
			if (row == 0)
				col = (col + 1) % 4;
			if (row == 0 && col == 0)
				roundKey++;
		}
		generateRoundKeys();
		
		try {
			String filename = args[2];
			File out;
			File data = new File(filename);
			s = new Scanner(data);
			while (s.hasNextLine()) {
				String currentLine = padInput(s.nextLine());
				System.out.println(currentLine);
				if (currentLine != null) {
					System.out.println("HERE");
					row = 0;
					col = 0;
					for (int byteCounter = 0; byteCounter < 32; byteCounter += 2) {
						String currentByte = currentLine.substring(byteCounter, byteCounter + 2);
						state[row][col] = Integer.parseInt(currentByte, 16);
						row = (row + 1) % 4;
						if (row == 0)
							col = (col + 1) % 4;
					}
					
					if (encryption) {
						out = new File(filename + ".enc");
						PrintWriter pw = new PrintWriter(out.getName(), "UTF-8");
						addRoundKey(0);
						int round = 1;
						while (round < 15) {
							subBytes(true);
							shiftRows();
							if (round != 14)
								mixColumns();
							addRoundKey(round);
							round++;
						}
						printState(pw);
						pw.close();
					} else {
						out = new File(filename + ".dec");
						PrintWriter pw = new PrintWriter(out.getName(), "UTF-8");
						int round = 14;
						while (round > 0) {
							addRoundKey(round);
							if (round != 14)
								invMixColumns();
							invShiftRows();
							subBytes(false);
							round--;
						}
						addRoundKey(0);
						printState(pw);
						pw.close();
					}
				}
			}
			s.close();
		} catch(IOException ioe) {}
	}
	
	// pad a line of input from input file
	public static String padInput(String input) {
		input = input.toUpperCase();
		if (input.length() > 32)
			input = input.substring(0, 32);
		else if (input.length() < 32) {
			while (input.length() < 32)
				input += "0";
		}
		for (int index = 0; index < input.length(); index++) {
			char current = input.charAt(index);
			if (current < 48 || current > 70 || (current > 57 && current < 65)) // not a hex character
				return null;
		}
		return input;
	}
	
	// print out state to output file
	public static void printState(PrintWriter pw) {
		for (int col = 0; col < state[0].length; col++) {
			for (int row = 0; row < state.length; row++) {
				String hex = Integer.toHexString(state[row][col]).toUpperCase();
				if (hex.length() < 2) // must have a leading zero that got cut
					hex = "0" + hex;
				pw.print(hex);
			}
		}
		pw.println();
	}
	
	public static void printState2() {
		for (int col = 0; col < state[0].length; col++) {
			for (int row = 0; row < state.length; row++) {
				String hex = Integer.toHexString(state[row][col]).toUpperCase();
				if (hex.length() < 2) // must have a leading zero that got cut
					hex = "0" + hex;
				System.out.print(hex);
			}
		}
		System.out.println();
	}
	
	// subBytes operation of AES algorithm,
	// encryption variable determines whether we are using
	// regular operation or inverse operation
	public static void subBytes(boolean encryption) {
		for (int row = 0; row < state.length; row++) {
			for (int col = 0; col < state[row].length; col++) {
				int rowIndex = state[row][col] >>> 4;
				int colIndex = state[row][col] & 0x0F;
				if (encryption)
					state[row][col] = S_BOX[rowIndex][colIndex];
				else
					state[row][col] = INV_S_BOX[rowIndex][colIndex];
			}
		}
	}
	
	// shiftRows operation of AES algorithm
	public static void shiftRows() {
		for (int row = 0; row < state.length; row++) {
			for (int shifts = 0; shifts < row; shifts++) {
				int current = state[row][state[row].length - 1];
				for (int col = state[row].length - 1; col >= 0; col--) {
					if (col > 0) {
						int temp = state[row][col - 1];
						state[row][col - 1] = current;
						current = temp;
					} else
						state[row][state[row].length - 1] = current;
				}
			}
		}
	}
	
	// inverse of the shiftRows operation
	public static void invShiftRows() {
		for (int row = 0; row < state.length; row++) {
			for (int shifts = 0; shifts < row; shifts++) {
				int current = state[row][0];
				for (int col = 0; col < state[row].length; col++) {
					if (col < state.length - 1) {
						int temp = state[row][col + 1];
						state[row][col + 1] = current;
						current = temp;
					} else
						state[row][0] = current;
				}
			}
		}
	}
	
	// mixColumns operation of the AES algorithm
	public static void mixColumns() {
		for (int col = 0; col < state[0].length; col++) {
			mixColumnsHelper(col);
		}
	}

    // In the following two methods, the input c is the column number in
    // your evolving state matrix st (which originally contained 
    // the plaintext input but is being modified).  Notice that the state here is defined as an
    // array of bytes.  If your state is an array of integers, you'll have
    // to make adjustments. 
    public static void mixColumnsHelper(int col) {
		// This is another alternate version of mixColumn, using the 
		// logtables to do the computation.
		
		int a[] = new int[4];
		
		// note that a is just a copy of st[.][c]
		for (int i = 0; i < 4; i++) 
		    a[i] = state[i][col];
		
		// This is exactly the same as mixColumns1, if 
		// the mul columns somehow match the b columns there.
		state[0][col] = mul(2,a[0]) ^ a[2] ^ a[3] ^ mul(3,a[1]);
		state[1][col] = mul(2,a[1]) ^ a[3] ^ a[0] ^ mul(3,a[2]);
		state[2][col] = mul(2,a[2]) ^ a[0] ^ a[1] ^ mul(3,a[3]);
		state[3][col] = mul(2,a[3]) ^ a[1] ^ a[2] ^ mul(3,a[0]);
    }
    
    // helper method for mixColumns
    public static int mul(int a, int b) {
		int inda = (a < 0) ? (a + 256) : a;
		int indb = (b < 0) ? (b + 256) : b;

		if ( (a != 0) && (b != 0) ) {
		    int index = (LOG_TABLE[inda] + LOG_TABLE[indb]);
		    int val = A_LOG_TABLE[ index % 255 ];
		    return val;
		}
		else 
		    return 0;
    }
    
    // inverse of the mix columns operation of AES algorithm
    public static void invMixColumns() {
    	for (int col = 0; col < state[0].length; col++) {
			invMixColumnsHelper(col);
		}
    }
    
    // helper method for invMixColumns
    public static void invMixColumnsHelper(int c) {
    	int a[] = new int[4];
    	
    	// note that a is just a copy of st[.][c]
    	for (int i = 0; i < 4; i++) 
    	    a[i] = state[i][c];
    	
    	state[0][c] = mul(0xE,a[0]) ^ mul(0xB,a[1]) ^ mul(0xD, a[2]) ^ mul(0x9,a[3]);
    	state[1][c] = mul(0xE,a[1]) ^ mul(0xB,a[2]) ^ mul(0xD, a[3]) ^ mul(0x9,a[0]);
    	state[2][c] = mul(0xE,a[2]) ^ mul(0xB,a[3]) ^ mul(0xD, a[0]) ^ mul(0x9,a[1]);
    	state[3][c] = mul(0xE,a[3]) ^ mul(0xB,a[0]) ^ mul(0xD, a[1]) ^ mul(0x9,a[2]);
	} // invMixColumn2

    
    // generate keys for rounds 2-14
    public static void generateRoundKeys() {
		int rcon = 1;
		for (int round = 2; round < 15; round++) {
			for (int col = 0; col < roundKeys[round][0].length; col++) {
				int prevCol = (col + 3) % 4;
				if (col == 0) {
					for (int row = 0; row < roundKeys[round].length; row++)
						roundKeys[round][row][col] = roundKeys[round - 1][row][prevCol];
					scheduleCore(round, rcon);
					for (int row = 0; row < roundKeys[round].length; row++)
						roundKeys[round][row][col] ^= roundKeys[round - 2][row][col];
				} else {
					for (int row = 0; row < roundKeys[round].length; row++) {
						roundKeys[round][row][col] = roundKeys[round][row][prevCol] ^ roundKeys[round - 2][row][col];
					}
				}
			}
			if (round % 2 == 0)
				rcon <<= 1;
		}
    }
    
    // function used the initial column of each roundKey
    public static void scheduleCore(int round, int rcon) {
    	// rotate each byte up one
    	if (round % 2 == 0) { // operation specific to even roundroundKeys
	    	int temp = roundKeys[round][0][0];
	    	for (int row = 0; row < 3; row ++)
	    		roundKeys[round][row][0] = roundKeys[round][row + 1][0];
	    	roundKeys[round][3][0] = temp;
    	}
    	
    	for (int row = 0; row < 4; row++) {
    		int rowIndex = (roundKeys[round][row][0] >>> 4);
			int colIndex = (roundKeys[round][row][0] & 0x0F);
			roundKeys[round][row][0] = S_BOX[rowIndex][colIndex];
    	}
    	
    	if (round % 2 == 0) // operation specific to even roundroundKeys
    		roundKeys[round][0][0] ^= rcon;
    }
	
    // addRoundKey operation of AES algorithm
	public static void addRoundKey(int round) {
		for (int row = 0; row < state.length; row++) {
			for (int col = 0; col < state[row].length; col++)
				state[row][col] ^= roundKeys[round][row][col];
		}
	}
	
}
