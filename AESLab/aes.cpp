#include <iostream>
#include <cstring>
#include "TableBoxLookUps.h"
using namespace std;


void subBytes(unsigned char* stateOfPlainText){
    //Every byte in the state, replaced with the subBox value
	int i = 0;
    while(i < 16){
        //each byte in the state becomes whatever the index of that bytes is in the subBox
		stateOfPlainText[i] = subBox[stateOfPlainText[i]];
        i++;
	}
}

void rotationRows(unsigned char* stateOfPlainText){

	/*
    0   4   8   12      0   4   8   12  shifted none
    1   5   9   13      5   9   13  1   shifted once
    2   6   10  14  ->  10  14  2   6   shifted twice
    3   7   11  15      15  3   7   11  shifted three
    */

    //rotation of Rows performed in tempVar
	unsigned char tempVar[16];

    //Row 1: Doesnt shift  
    tempVar[0] = stateOfPlainText[0];   
    tempVar[4] = stateOfPlainText[4];  
    tempVar[8] = stateOfPlainText[8];
    tempVar[12] = stateOfPlainText[12];

    //Row 2: Shifts right once
    tempVar[1] = stateOfPlainText[5];
    tempVar[5] = stateOfPlainText[9];
    tempVar[9] = stateOfPlainText[13];
    tempVar[13] = stateOfPlainText[1];

    //Row 3: Shifts right twice
    tempVar[2] = stateOfPlainText[10];
    tempVar[6] = stateOfPlainText[14];
    tempVar[10] = stateOfPlainText[2];
    tempVar[14] = stateOfPlainText[6];

    //Row 4: Shifts right 3 times 
    tempVar[3] = stateOfPlainText[15];
    tempVar[7] = stateOfPlainText[3];
    tempVar[11] = stateOfPlainText[7];
    tempVar[15] = stateOfPlainText[11];

    //Copy tempVar to stateOfPlainText after finished shifting the rows
    int i =0;
    while(i < 16){
        stateOfPlainText[i] = tempVar[i];
        i++;
    }

}

void MixColumns(unsigned char* stateOfPlainText){
    int i = 0;
	unsigned char tempVar[16];

    //saves results temporarily to tempVar by use of mul2 and mul3 look up tables in TableBoxLookUps.h
    //Galois multiplication: 10 2, 11 2 % 100011011 2   Matrix multiplcation
    while(i < 4){
        tempVar[(4*i)+0] = (unsigned char)(mul2[stateOfPlainText[(4*i)+0]] ^ mul3[stateOfPlainText[(4*i)+1]] ^ stateOfPlainText[(4*i)+2] ^ stateOfPlainText[(4*i)+3]);
        tempVar[(4*i)+1] = (unsigned char)(stateOfPlainText[(4*i)+0] ^ mul2[stateOfPlainText[(4*i)+1]] ^ mul3[stateOfPlainText[(4*i)+2]] ^ stateOfPlainText[(4*i)+3]);
        tempVar[(4*i)+2] = (unsigned char)(stateOfPlainText[(4*i)+0] ^ stateOfPlainText[(4*i)+1] ^ mul2[stateOfPlainText[(4*i)+2]] ^ mul3[stateOfPlainText[(4*i)+3]]);
        tempVar[(4*i)+3] = (unsigned char)(mul3[stateOfPlainText[(4*i)+0]] ^ stateOfPlainText[(4*i)+1] ^ stateOfPlainText[(4*i)+2] ^ mul2[stateOfPlainText[(4*i)+3]]);
        i++;
    }

    //copy over to stateOfPlainText
    for(int i = 0; i < 16; i++){
		stateOfPlainText[i] = tempVar[i];
	}

}

void addRoundKey(unsigned char* stateOfPlainText, unsigned char* roundkey){
	//XOR Binary addition Galois Fields
	int i = 0; 
	while(i < 16){
		stateOfPlainText[i] ^= roundkey[i];
		i++;
	}
}

//takes 4 bytes from keys generated, XORs the 4 bytes generated
void coreExpansion(unsigned char* in, unsigned char i){
	//rotates left
	unsigned char t = in[0];
	in[0] = in[1];
	in[1] = in[2];
	in[2]= in[3];
	in[3] = t;

    //subBox box 4 bytes, swaps each byte with the corresponding value from the rijndael sbox(lookup table)
	in[0] = subBox[in[0]];
	in[1] = subBox[in[1]];
	in[2] = subBox[in[2]];
	in[3] = subBox[in[3]];

    //Rcon, raise 2 to the power of i - 1 where i is the iteration number and then add it to value of the first byte in the 4
    in[0] ^= Rcon[i];
}

void finalRound(unsigned char* text, unsigned char* stateOfPlainText, unsigned char* expandedKey){
	//Final Round takes in no mix columns
	subBytes(stateOfPlainText);
	rotationRows(stateOfPlainText);

	//final key in expandedKeys begins at expandedKey + 16
	addRoundKey(stateOfPlainText, expandedKey + 160);//every 16 bytes in expandedKey is a new round key

	//copy over the text with the encrypted text
	//copies over the original text with whatever the stateOfPlainText is
	int i = 0;
	while(i < 16){
		text[i] = stateOfPlainText[i];
		i++;
	}
}


void Encryption(unsigned char* text, unsigned char* key){

	unsigned char expandedKey[176];//define character array of 176 bytes
//key expansion below
//takes 16 bytes and expands it to 176 bytes
/*Copies the original 128 bit key to the first 16  bytes of the expanded key*/
// takes original key so the first 16 bytes and then the expnadedkey is the same as the original key

// //the first 16 bytes are the original key
    for(int i = 0; i < 16; i++){
	expandedKey[i] = key[i];
}
//keep track of how many bytes we've generated, the Rcon iteration value, and we need a
//temp varaible for when we call the core
int bytesGenerated = 16;
int rconIteration = 1;
unsigned char temp[4];//temp storage for core

while(bytesGenerated < 176){
	// Reads the previously generated 4 bytes for the core
	//bytes for core are the previously generated 4 bytes which will be the final 4 bytes of the original key
	for(int i = 0; i < 4; i++){
		temp[i] = expandedKey[i + bytesGenerated - 4];
	}
	//perform the core once for each 16 byte key: once every new key, perform the core with temp and the current Rcon iteration value, 
    //we then increment the iteration value
	//keys are of length 16 bytes so we do this whenever bytesGenerated%16 is 0
	if(bytesGenerated % 16 == 0){
		coreExpansion(temp, rconIteration++);
	}
	//Add XOR temp to the bytes 16 from the bytes generated. store temp as the newly generated bytes in expandedkey and increment the bytesGenerated by 4
	//XOR temp with [bytesGenerates-16], and store in expandedKeys:
	for(unsigned char a = 0; a < 4; a++){
		expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 16] ^ temp[a];
		bytesGenerated++;
	}
}
	int j = 0;
	int k = 0;
	unsigned char stateOfPlainText[16];
	//copying text to stateOfPlainText, can encrypt in place in  text but we are doing it in blocks
	while(j < 16){
		stateOfPlainText[j] = text[j];
		j++;
	}
	int totalRounds = 9;//we do a total of 9 rounds

	addRoundKey(stateOfPlainText, key);//InitialRound, whitening

	//run through however many rounds there are
	while(k < totalRounds) {
		subBytes(stateOfPlainText);
		rotationRows(stateOfPlainText);
		MixColumns(stateOfPlainText);

		//when we call addRoundKey in the loop use the expanded keys. the expanded key
		//for each round is the 16 bytes corresponding to the round number
		addRoundKey(stateOfPlainText, expandedKey+(16*(k + 1)));//16 times the round index
		k++;
	}
	finalRound(text, stateOfPlainText, expandedKey);
}

void outputEncryptedText(int paddedTextLength, unsigned char* paddedText){
//Printing out of Encrypted Text
cout<<"Encrypted text: " << endl;
int i = 0;
while(i < paddedTextLength){
	if(paddedText[i]/16 < 10){ 
        cout<<(char)((paddedText[i]/16) + '0');
    }
	if(paddedText[i]/16 >= 10){
         cout<<(char)((paddedText[i]/16 - 10) + 'A');
    }
	if(paddedText[i]%16 < 10){ 
        cout<<(char)((paddedText[i]%16) + '0');
    }
	if(paddedText[i]%16 >= 10) {
        cout<<(char)((paddedText[i]%16-10) + 'A');
    }
	cout<< " ";
    i++;
}
cout << endl;
}

void paddingPlainText(char* text, unsigned char* key){
	//pads message to 16 bytes with 0's, calls encryption for each 16 byte block

	int textOriginalLength = strlen((const char*) text);
	int paddedTextLength = textOriginalLength;

	//rounds up to nearest multiple of 16
	if(paddedTextLength % 16 != 0){
		paddedTextLength = (paddedTextLength / 16 + 1) * 16;
	}

	//copies originalmessage to the padded text
	unsigned char* paddedText = new unsigned char[paddedTextLength];
	int i = 0;
	while(i < paddedTextLength){
		//adds 0'subBox to fill up the text so that it equals 16 bytes
		if(i >= textOriginalLength) {
			paddedText[i] = 0;
		} else {
			paddedText[i] = text[i];
		}
		i++;
	}

	//encrypt padded text:
	int j = 0;
	while(j < paddedTextLength) {
		Encryption(paddedText+j, key);
		j+=16;
	}
		outputEncryptedText(paddedTextLength, paddedText);
}


int main(){

//Key of 16 bytes
unsigned char key[16] = 
{
	1, 2, 3, 4,
	5, 6, 7, 8,
	9, 10, 11, 12,
	13, 14, 15, 16,
};

//Making size for array of char
int size;
cout << "Enter size of text: " << endl;
cin >> size;
char text[size];

//User enters their message
cout << "Enter plaintext: " << endl;
cin.ignore();
cin.getline(text, size+1);


paddingPlainText(text, key);

return 0;
}





