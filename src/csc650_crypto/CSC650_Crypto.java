package csc650_crypto;

import java.util.*;

public class CSC650_Crypto {
       
    //Converts a string to an int array
    static int[] string_to_intArray(String s) {
        int[] array = new int[s.length()*8];
        for (int i = 0; i <= s.length() - 1; i++) {
            String str = Integer.toBinaryString(s.charAt(i));
            do { str = "0" + str; } while (str.length() <= 7);
            for (int j = 0; j <= 7; j++) {
                array[j + (i * 8)] = Integer.parseInt(str.substring(j, j + 1));
            }
        }
        return array;
    }      
    
    //Prints an int array
    static void print(int[] ciphertext) {
        System.out.print("{");
        for (int i = 0; i < ciphertext.length; i++) {
            System.out.print(ciphertext[i] + ", ");
        }
        System.out.println("}");
    }

    //mangler function to be used in DES function
    //in the f calculation, we XOR the output E(Rn-1) with the key Kn
    static int[] mangler_function(int[] key, int[] dataBlock) {
        /*Initializations*/
        int[] E = new int[48]; // expand the dataBlock to 48 bits
        int[] result = new int[48]; // store the result of XORing the expanded block with key
        int[][] Bn = new int[8][6]; //8 blocks of 6 bits
        
        //set up the Sboxes
        int[][][] Sn = 
        {
            { {14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
                {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
                {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
                {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13} 
            },
            { {15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
                {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
                {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
                {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9} 
            },
            { {10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
                {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
                {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
                {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12} 
            },
            { {7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
                {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
                {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
                {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14} 
            },
            { {2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
                {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
                {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
                {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3} 
            },
            { {12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
                {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
                {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
                {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13} 
            },
            { {4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
                {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
                {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
                {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12} 
            },
            { {13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
                {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
                {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
                {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11} 
            } 
        };
        
        String[] row = new String[8]; //used for expanded block
        String[] col = new String[8]; //used for expanded block
        int[] decRow = new int[8]; //used to convert sboxes to decimal
        int[] decCol = new int[8];  //used to convert sboxes to decimal    
        String[] decSn = new String[8]; //used to store sbox rows and cols
        int[] S_output = new int[32]; //used to convert sboxes to decimal
        int[] f = new int[32]; //stores the permutated array, final result for mangler function
        
        /*STEP 1*/
        //Expand dataBlock to 48 bits
        E[0] = dataBlock[31]; //first element
        E[47] = dataBlock[0]; //last element
        
        //Loop through block and permute
        //Decrement by 1
        for (int i = 1; i <= 5; i++) { E[i] = dataBlock[i - 1]; }
        for (int i = 6; i <= 11; i++) { E[i] = dataBlock[i - 3]; }
        for (int i = 12; i <= 17; i++) { E[i] = dataBlock[i - 5]; }
        for (int i = 18; i <= 23; i++) { E[i] = dataBlock[i - 7]; }
        for (int i = 24; i <= 29; i++) { E[i] = dataBlock[i - 9]; }
        for (int i = 30; i <= 35; i++) { E[i] = dataBlock[i - 11]; }
        for (int i = 36; i <= 41; i++) { E[i] = dataBlock[i - 13]; }
        for (int i = 42; i <= 46; i++) { E[i] = dataBlock[i - 15]; }
        
        /*STEP 2*/
        //Kn + E(Rn-1)
        //'+' denotes XOR
        for (int i = 0; i <= 47; i++) { result[i] = E[i] ^ key[i]; } //XOR
        
        /*STEP 3*/
        //now have 48 bits, or eight groups of six bits. We now do
        //something strange with each group of six bits: we use them as addresses in tables
        //called "S boxes". Each group of six bits will give us an address in a different S box
        //S1(B1)S2(B2)S3(B3)S4(B4)S5(B5)S6(B6)S7(B7)S8(B8)
        //where Si(Bi) refers to the output of the i-th S box.
        
        for (int i = 0; i <= 7; i++) { System.arraycopy(result, i * 6, Bn[i], 0, 6); }
        
        /*STEP 4*/
        //6 bits = 4 inner bits from col and 2 outer bits from row
        //The first and last bits of B represent in base 2 a number in the
        //decimal range 0 to 3 (or binary 00 to 11). Let that number be i. The middle 4 bits
        //of B represent in base 2 a number in the decimal range 0 to 15 (binary 0000 to 1111).
        for(int i = 0; i <= 7; i++) { 
            row[i] = "" + Bn[i][0] + Bn[i][5];
            col[i] = "" + Bn[i][1] + Bn[i][2] + Bn[i][3] + Bn[i][4];
        }
        
        /*STEP 5*/
        //Convert the row and col to decimal arrays
        for (int i = 0; i < 8; i++) {
            decRow[i] = Integer.parseInt(row[i], 2);
            decCol[i] = Integer.parseInt(col[i], 2);
        }
        
        /*STEP 6*/
        //Convert decimal Sn to string
        for (int i = 0; i <= 7; i++) { decSn[i] = Integer.toBinaryString(Sn[i][decRow[i]][decCol[i]]); }
        
        /*STEP 7*/
        //Pad 0's to decSn elements that have a length of 3 or less
        for (int i = 0; i <= 7; i ++) { while (decSn[i].length() <= 3) { decSn[i] = "0" + decSn[i]; } }
        
        /*STEP 8*/
        //The final stage in the calculation of f is to do a permutation P of the S-box output to
        //obtain the final value of f, 32 bits:
        //f = P(S1(B1)S2(B2)...S8(B8))
        for (int i = 0; i <= 7; i++) {
            for (int j = 0; j <= 3; j++) { S_output[j + (i * 4)] = Integer.parseInt(decSn[i].substring(j, j + 1)); }
        }
        
        //Permutate the 32 bit array, decrement by 1
        f[0]  = S_output[15]; f[1]  = S_output[6]; f[2]  = S_output[19]; f[3]  = S_output[20];
        f[4]  = S_output[28]; f[5]  = S_output[11]; f[6]  = S_output[27]; f[7]  = S_output[16];
        f[8]  = S_output[0];  f[9]  = S_output[14]; f[10] = S_output[22]; f[11] = S_output[25];
        f[12] = S_output[4];  f[13] = S_output[17]; f[14] = S_output[30]; f[15] = S_output[9];
        f[16] = S_output[1];  f[17] = S_output[7]; f[18] = S_output[23]; f[19] = S_output[13];
        f[20] = S_output[31]; f[21] = S_output[26]; f[22] = S_output[2];  f[23] = S_output[8];
        f[24] = S_output[18]; f[25] = S_output[12]; f[26] = S_output[29]; f[27] = S_output[5];
        f[28] = S_output[21]; f[29] = S_output[10]; f[30] = S_output[3];  f[31] = S_output[24];
        
        return f;
        
    }
    

    public static int[] DES(int[] plaintext, int[] key) {
        /*Initializations*/
        int[] P1 = new int[56]; //stores the permutated key
        int[][] key_L = new int[17][28]; //splits the key into two 28-bit int 2Darrays
        int[][] key_R = new int[17][28]; //splits the key into two 28-bit int 2Darrays
        int[][] key_LR = new int[16][56]; //combines keyL and keyR after per round shifts
        int[][] keys = new int[16][48]; //permutates the key
        int[] ip = new int[64]; //stores the initial permutation of the plaintext
        int[][] Ln = new int[17][32]; //splits ip into two 32-bit int 2Darrays
        int[][] Rn = new int[17][32]; //splits ip into two 32-bit int 2Darrays
        int[][] mangler = new int[16][32]; //stores the array after using mangler function
        int[] R16L16 = new int[64]; //combines ln and rn after mangler function
        int[] ciphertext = new int[64]; //stores in the ciphertext after reversing r16l16, final result
                
        //Check to make sure plaintext and key are 64-bits long
        if (plaintext.length != 64 || key.length != 64) {
            System.err.println("Error: Size not equal to 64");
            System.exit(1);
        }
        
        /*STEP 1: Create 16 per-round keys, each of which is 48-bits long.*/
        //Permutate the key using 56-bits using the example table given in DES Example.pdf
        //Since position of arrays goes from 0-63, decrement 1 for each position

        P1[0]  = key[56]; P1[1]  = key[48]; P1[2]  = key[40];
        P1[3]  = key[32]; P1[4]  = key[24]; P1[5]  = key[16];
        P1[6]  = key[8];  P1[7]  = key[0];  P1[8]  = key[57];
        P1[9]  = key[49]; P1[10] = key[41]; P1[11] = key[33];
        P1[12] = key[25]; P1[13] = key[17]; P1[14] = key[9];
        P1[15] = key[1];  P1[16] = key[58]; P1[17] = key[50];
        P1[18] = key[42]; P1[19] = key[34]; P1[20] = key[26];
        P1[21] = key[18]; P1[22] = key[10]; P1[23] = key[2];
        P1[24] = key[59]; P1[25] = key[51]; P1[26] = key[43];
        P1[27] = key[35]; P1[28] = key[62]; P1[29] = key[54];
        P1[30] = key[46]; P1[31] = key[38]; P1[32] = key[30];
        P1[33] = key[22]; P1[34] = key[14]; P1[35] = key[6];
        P1[36] = key[61]; P1[37] = key[53]; P1[38] = key[45];
        P1[39] = key[37]; P1[40] = key[29]; P1[41] = key[21];
        P1[42] = key[13]; P1[43] = key[5];  P1[44] = key[60];
        P1[45] = key[52]; P1[46] = key[44]; P1[47] = key[36];
        P1[48] = key[28]; P1[49] = key[20]; P1[50] = key[12];
        P1[51] = key[4];  P1[52] = key[27]; P1[53] = key[19];
        P1[54] = key[11]; P1[55] = key[3];     
        
        
        //Combine arrays
        System.arraycopy(P1, 0, key_L[0], 0, 28);
        System.arraycopy(P1, 28, key_R[0], 0, 28);
        
        //Permute key_round array: left shift 1 for rounds 1,2,9,16; else left shift 2
        for (int i = 1; i <= 16; i++) {
            for (int j = 0; j <= 25; j++) {
                if (i == 1 || i == 2 || i == 9 || i == 16) {
                    key_L[i][j] = key_L[i-1][j+1];
                    key_R[i][j] = key_R[i-1][j+1];                                              
                } else {  
                    key_L[i][j] = key_L[i-1][j+2];
                    key_R[i][j] = key_R[i-1][j+2];
                }
            }
            if (i == 1 || i == 2 || i == 9 || i == 16) {
                key_L[i][26] = key_L[i-1][27];
                key_L[i][27] = key_L[i-1][0];
                key_R[i][26] = key_R[i-1][27];
                key_R[i][27] = key_R[i-1][0];                
            } else {
                key_L[i][26] = key_L[i-1][0];
                key_L[i][27] = key_L[i-1][1];
                key_R[i][26] = key_R[i-1][0];
                key_R[i][27] = key_R[i-1][1];                
            }
        }
        
        //Combine key_L and key_R, 16 rounds, 56-bits
        for (int i = 0; i <= 15; i++) {
            for (int j = 0; j <= 27; j++) {
                key_LR[i][j] = key_L[i+1][j]; 
                key_LR[i][j+28] = key_R[i+1][j]; 
            }
        }
        
        //Permutate key_LR to get 16 per-round keys using the example table given in DES Example.pdf
        //Decrement by 1 since array starts from 0
        for (int i = 0; i <= 15; i++) {
            keys[i][0]  = key_LR[i][13]; keys[i][1]  = key_LR[i][16]; keys[i][2]  = key_LR[i][10]; keys[i][3]  = key_LR[i][23];
            keys[i][4]  = key_LR[i][0];  keys[i][5]  = key_LR[i][4]; keys[i][6]  = key_LR[i][2];  keys[i][7]  = key_LR[i][27];
            keys[i][8]  = key_LR[i][14]; keys[i][9]  = key_LR[i][5]; keys[i][10] = key_LR[i][20]; keys[i][11] = key_LR[i][9];
            keys[i][12] = key_LR[i][22]; keys[i][13] = key_LR[i][18]; keys[i][14] = key_LR[i][11]; keys[i][15] = key_LR[i][3];
            keys[i][16] = key_LR[i][25]; keys[i][17] = key_LR[i][7]; keys[i][18] = key_LR[i][15]; keys[i][19] = key_LR[i][6];
            keys[i][20] = key_LR[i][26]; keys[i][21] = key_LR[i][19]; keys[i][22] = key_LR[i][12]; keys[i][23] = key_LR[i][1];
            keys[i][24] = key_LR[i][40]; keys[i][25] = key_LR[i][51]; keys[i][26] = key_LR[i][30]; keys[i][27] = key_LR[i][36];
            keys[i][28] = key_LR[i][46]; keys[i][29] = key_LR[i][54]; keys[i][30] = key_LR[i][29]; keys[i][31] = key_LR[i][39];
            keys[i][32] = key_LR[i][50]; keys[i][33] = key_LR[i][44]; keys[i][34] = key_LR[i][32]; keys[i][35] = key_LR[i][47];
            keys[i][36] = key_LR[i][43]; keys[i][37] = key_LR[i][48]; keys[i][38] = key_LR[i][38]; keys[i][39] = key_LR[i][55];
            keys[i][40] = key_LR[i][33]; keys[i][41] = key_LR[i][52]; keys[i][42] = key_LR[i][45]; keys[i][43] = key_LR[i][41];
            keys[i][44] = key_LR[i][49]; keys[i][45] = key_LR[i][35]; keys[i][46] = key_LR[i][28]; keys[i][47] = key_LR[i][31];            
        }
        
        /*STEP 2: Encode each 64-bit block of data*/
        
        //2 in position 8, 4 in position 16, etc
        //See DES example.pdf for table
        for (int i = 0; i <= 7; i++) {
            ip[(8 * 1) - (i + 1)] = plaintext[(8 * i) + 1]; //2
            ip[(8 * 2) - (i + 1)] = plaintext[(8 * i) + 3]; //4
            ip[(8 * 3) - (i + 1)] = plaintext[(8 * i) + 5]; //6    
            ip[(8 * 4) - (i + 1)] = plaintext[(8 * i) + 7]; //8
            ip[(8 * 5) - (i + 1)] = plaintext[(8 * i) + 0]; //1
            ip[(8 * 6) - (i + 1)] = plaintext[(8 * i) + 2]; //3
            ip[(8 * 7) - (i + 1)] = plaintext[(8 * i) + 4]; //5
            ip[(8 * 8) - (i + 1)] = plaintext[(8 * i) + 6]; //7
        }
        
        //Divide the permuted block IP into a left half Ln of 32 bits, and a right half Rn of 32 bits
        System.arraycopy(ip, 0, Ln[0], 0, 32);
        System.arraycopy(ip, 32, Rn[0], 0, 32);
        
        
        /*STEP 3*/
        //Perform mangler function on L0 and R0
        //Ln = Rn -1
        //Rn = Ln-1 + f(Rn-1 , Kn )
        for (int i = 1; i <= 16; i++) {
            Ln[i] = Rn[i - 1];
            
            mangler[i - 1] = mangler_function(keys[i - 1],Rn[i - 1]); 
            for (int j = 0; j <= 31; j++) { Rn[i][j] = Ln[i - 1][j] ^ mangler[i - 1][j]; }
        }
        
        /*STEP 4*/
        //At the end of the sixteenth round we have the blocks L16 and R16. 
        //We then reverse the order of the two blocks into the 64-bit block R16L16 
        //and apply a final permutation IP^-1
        for (int i = 0; i <= 31; i++) {
            R16L16[i] = Rn[16][i];
            R16L16[i + 32] = Ln[16][i];
        }
        
        //obtain the ciphertext
        for (int i = 0; i <= 7; i++) {
            ciphertext[(8*i) + 0] = R16L16[(8*5) - (i+1)];
            ciphertext[(8*i) + 1] = R16L16[(8*1) - (i+1)];
            ciphertext[(8*i) + 2] = R16L16[(8*6) - (i+1)];
            ciphertext[(8*i) + 3] = R16L16[(8*2) - (i+1)];
            ciphertext[(8*i) + 4] = R16L16[(8*7) - (i+1)];
            ciphertext[(8*i) + 5] = R16L16[(8*3) - (i+1)];
            ciphertext[(8*i) + 6] = R16L16[(8*8) - (i+1)];
            ciphertext[(8*i) + 7] = R16L16[(8*4) - (i+1)];            
        }
        
        return ciphertext;    
    }
    
    
    public static int[] ECB(String plaintext, String key) {
        /*Initializations*/
        int[] p_bin = string_to_intArray(plaintext); //Convert plaintext string into int array
        int[] key_bin = string_to_intArray(key); //key string into int array
        int[] key_final = new int[64]; //stores the key
        int[][] blocks = new int[p_bin.length/64][64]; //stores the blocks in a 2Darray
        int[][] Eblocks = new int[blocks.length][64]; //stores the blocks after encryption
        int[] E_array = new int[Eblocks.length*64]; //combines all results in one array
        String[] c_str = new String[E_array.length / 8]; //used to convert earray to string
        int[] ciphertext = new int[c_str.length]; //used to convert str to decimal and stores result, final result
        
        //If the size of the integer array obtained from the string variable key is less than 64, 
        //throw away an error message
        if (key_bin.length != 64) {
            System.err.println("Error: Size not equal to 64");
            System.exit(1);            
        }
        
        /*STEP 1*/
        //Extract the subarray consisting of the first 64 elements as the key to DES encryption algorithm
        //When you breaks the integer array obtained from the string variable
        //plaintext into 64-bit blocks, pad 0 to the last block if its size is less than 64
        System.arraycopy(key_bin, 0, key_final, 0, 64);
        
        if (p_bin.length % 64 == 0) {
            blocks = new int[p_bin.length/64][64];
            for (int i = 0; i <= blocks.length - 1; i++) {
                System.arraycopy(p_bin, (i*64), blocks[i], 0, 64);
            }
        } else {
            //need to pad 0's
            blocks = new int[(p_bin.length/64)+1][64];
            for (int i = 0; i <= blocks.length - 2; i++) {
                System.arraycopy(p_bin, (i*64), blocks[i], 0, 64);
            }
            System.arraycopy(p_bin,(p_bin.length/64)*64, blocks[blocks.length-1],0, p_bin.length%64);
        }
        
        /*STEP 2*/
        //Encrypt each block using DES
        for (int i = 0; i <= Eblocks.length - 1; i++) {
            Eblocks[i] = DES(blocks[i],key_final);
        }
        
        /*STEP 3*/
        //Concatenate the outputs into one integer array
        for (int i = 0; i <= (E_array.length/64) - 1; i++) {
            System.arraycopy(Eblocks[i], 0, E_array, (i * 64), 64);
        }
        
        /*STEP 4*/
        //Then, group every 8 elements in the array as one ASCII code
        for (int i = 0; i <= (E_array.length / 8) - 1; i++) {
            c_str[i] = "";
            for (int j = 0; j < 8; j++) {
                c_str[i] += E_array[(i*8)+j];
            }
        }   
        
        /*STEP 5*/
        //convert it into its decimal format
        for (int i = 0; i < ciphertext.length; i++) {
            int decimal = Integer.parseInt(c_str[i], 2);
            ciphertext[i] = decimal;
        }
        
        return ciphertext;
    }
    
    public static int[] CBC(String plaintext, String key, String IV) {
        /*Initializations*/
        int[] p_bin = string_to_intArray(plaintext); //Convert plaintext string into int array
        int[] key_bin = string_to_intArray(key); //Convert key string into int array
        int[] iv_bin = string_to_intArray(IV); //Convert iv string into int array
        int[] key_final = new int[64]; //stores the key
        int[][] blocks = new int[p_bin.length/64][64]; //stores the blocks in a 2Darray
        int[] ciphertext = new int[64]; //used to convert str to decimal and stores result, final result
        
        //If the size of the integer array obtained from the string variable key is less
        //than 64, throw away an error message
        if (key_bin.length != 64 || iv_bin.length != 64) {
            System.err.println("Size not equal to 64");
            System.exit(1);
        }
        
        /*STEP 1*/
        //extract the subarray consisting of the first 64 elements as the key to DES encryption algorithm
        System.arraycopy(key_bin, 0, key_final, 0, 64);
        int[] iv_final = new int[64];
        System.arraycopy(iv_bin, 0, iv_final, 0, 64);  
        
        if (p_bin.length % 64 == 0) {
            blocks = new int[p_bin.length/64][64];
            for (int i = 0; i <= blocks.length - 1; i++) {
                System.arraycopy(p_bin, (i*64), blocks[i], 0, 64);
            }
        } else {
            //need to pad 0's
            blocks = new int[(p_bin.length/64)+1][64];
            for (int i = 0; i <= blocks.length - 2; i++) {
                System.arraycopy(p_bin, (i*64), blocks[i], 0, 64);
            }
            System.arraycopy(p_bin,(p_bin.length/64)*64, blocks[blocks.length-1],0, p_bin.length%64);
        }        
        
        //XOR iv_final with first block of blocks

        
        //Encrypt each block using DES

        
        //concatenate the outputs into one integer array
  
        
        //Then, group every 8 elements in the array as one ASCII code
      
        
        //Convert it into its decimal format
        
        return ciphertext;        
    }
    
    public static void main(String args[]) {
        
            //TEST DES FUNCTION
            int[] plaintext = {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
            0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 1,
            0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 1,
            1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1};
            int[] key = {0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0,
            0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0,
            1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1,
            1, 1, 1, 1, 1, 0, 0, 0, 1};    
            int[] ciphertext = DES(plaintext,key);
            print(ciphertext);
            String s = "hello";
            int[] arr = string_to_intArray(s);
            print(arr);
            
            //TEST ECB FUCNTION
            String E_plaintext = "I LOVE SECURITY";
            String E_key = "ABCDEFGH";
            int[] E_ciphertext = ECB(E_plaintext,E_key);
            print(E_ciphertext);
            
            //TEST CBC FUNCTION
            String C_plaintext = "I LOVE SECURITY";
            String C_key = "ABCDEFGH";
            String IV = "ABCDEFGH";
            int[] C_ciphertext = CBC(C_plaintext,C_key, IV);
            print(C_ciphertext);   
        
    }

}