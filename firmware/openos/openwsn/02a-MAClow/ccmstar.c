#include "ccmstar.h"

void CCMstar(OpenQueueEntry_t* pkt,unsigned long long int key){

	uint8_t i;
	length = pkt->length-14;
	for(i=0; i<length;i++){
			payloadToEncrypt[i] = pkt->payload[14+i];
		}

	Input_Transformation(payloadToEncrypt,length);

	Auth_Transformation(length,key,0);

	Encr_Transformation(payloadToEncrypt,length,key,T,0);

	packetfunctions_reserveFooterSize(pkt,pkt->l2_authenticationLength);

	for(i=0;i<length+pkt->l2_authenticationLength;i++){
			pkt->payload[14+i] = CipherText[i];
					}
}


void Input_Transformation(uint8_t* payload,uint8_t length){

	//initialize AuthData
	uint8_t l,i;
	for(i=0; i<132;i++){
			authData[i] = 0;
		}
	authDataLength = 0;

	uint32_t La;

	//no authentication
	if(authlen == 0){
		La = 0;
		l = 0;
	}
	//authentication field of 32 bit
	if(authlen > 0 && authlen < 65280 ){//65280 = 2^16-2^8
		La = authlen;
		l = authlen;
	}
	//authentication field of 64 bit
	/*if(authlen >= 65280){
		La = 0xFF;
		La |= 0xFE << 8;
		La |= ((uint32_t)authlen) << 16;
		l = authlen + 2;
	}
	//this cannot be supported by this hw
	//authentication field of 128 bit
	/*if(authLen > (2^32)){
		L = 0xFF;
		L |= 0xFE <<8;
		L |= authLen <<16;
		l = authLen + 2;
	}*/

	for(i=0; i<4;i++){
		authData[i] = La << 8*i;
	}

	authData[i] = authlen;
	authDataLength = i+1;

	for(i=0;i<authDataLength+length;i++){
		authData[authDataLength+i] = payload[i];
	}
	authDataLength = authDataLength+length;

	uint8_t count;
	count = 16-(authDataLength-((authDataLength/16)*16));

	authDataLength = authDataLength+count;

}

void Auth_Transformation(uint8_t length,unsigned long long int key,bool encOrDec){

	uint8_t B[16];
	uint8_t X[16];

	//determine Flags Field
	B[0] = 0;
	B[0] = B[0] <<1;//1b reserved
	if(length == 0){
		B[0]= B[0] <<1;
	}
	else{
		B[0] |= 1 <<1;
	}

	if(authlen == 0){
		B[0]= B[0] <<2;
	}
	else{
		B[0] = B[0] <<2;
		B[0] |= ((authlen-2)/2)&0x07;
	}


	B[0] = B[0] <<3;
	B[0] |= length &0x07;

	//determine B0 fields
	uint8_t i;
	for(i=0;i<13;i++){
		B[i+1] = nonce[i];
	}

	for(i=0;i<5;i++){
		T[i] = 0;
	}

	uint32_t auxlen;
	auxlen = length;

	B[14] = auxlen;
	B[15] = auxlen <<8;

	//initialize X, for me IN
	for(i=0;i<16;i++){
		in[i] = 0;
	}
	//IV
	for(i=0;i<16;i++){
		in[i] = in[i]^B[i];
	}

	//Key Expansion phase, before the crypto block
	if(encOrDec==0){
		unsigned long long int newkey;
		newkey = key;
		for(i=0;i<8;i++){
				Key[i] = newkey;
				newkey = newkey >> 8;
			}

		KeyExpansion();
	}

	//crypto block
	uint8_t j;
	for(i=0;i<(authDataLength/16)+1;i++){
		for(j=i*16;j<i+16;j++){
			B[j-16*i] = authData[j];
			in[j-16*i] = B[j-16*i]^in[j-16*i];
		}

		AES_Cipher();

		for(j=0;j<16;j++){
			in[j] = out[j];
		}

	}


	for(i=0;i<authlen;i++){
		if(encOrDec==0){
			T[i] = out[i];
		}
		if(encOrDec==1){
			MACTag[i] = out[i];
		}
		}
}

void Encr_Transformation(uint8_t*  payload,
						 uint8_t   length,
		                 unsigned long long int key,
		                 uint8_t*  Ta,
		                 bool      cipher){

	uint8_t PlainTextData[16];
	uint8_t i;
	uint16_t cnt;

	cnt = 0;
	//initialization of CipherText
	for(i=0;i<128;i++){
		CipherText[i] = 0;
	}

	//Ai
	in[0] = 0;

	in[0] |= length &0x07 ; //flags field
	for(i=0;i<13;i++){
		in[i+1] = nonce[i];
	}

	in[14] = cnt;
	in[15] = cnt << 8;


	//encrypted auth tag
	AES_Cipher();

	if(cipher==0){
		for(i=0;i<authlen;i++){
			U[i] = out[i] ^ Ta[i];
		}

	}

	if(cipher==1){
		for(i=0;i<authlen;i++){
					W[i] = out[i] ^ Ta[i];
				}
	}

	uint8_t j;
	for(i=0;i<((length/16)+1);i++){
		for(j=i*16;j<i*16+16;j++){
			PlainTextData[j-16*i] = payload[j];
		}
		//update Nonce
		in[14] = cnt;
		in[15] = cnt << 8;


		AES_Cipher();
		cnt++;
		for(j=0;j<16;j++){
			out[j] = out[j] ^ PlainTextData[j];
			CipherText[j+16*i] = out[j];
		}
	}


	uint8_t count;
	count = 16-(length-((length/16)*16));
	for(i=(count-1);i>(length-1);i--){
		CipherText[i] = 0;
	}

	if(cipher==0){
		for(i=0;i<authlen;i++){
			CipherText[length+i] = U[i];
		}
	}

	if(cipher==1){
		for(i=0;i<authlen;i++){
					CipherText[length+i] = W[i];
				}
	}

}

void CCMstarInverse(OpenQueueEntry_t* pkt,unsigned long long int key){

	length = pkt->length;
	if(length == 0) return;

	uint8_t i;
	for(i=0; i<132;i++){
				payloadToEncrypt[i] = 0;
			}

	for(i=0; i<length;i++){
		payloadToEncrypt[i] = pkt->payload[i];
	}

	for(i=0;i<4;i++){
		MACTag[i] = 0;
	}

	decr_Transformation(payloadToEncrypt,length,pkt->l2_authenticationLength,key);

	auth_checking(payloadToEncrypt,length,key);

	for(i=0;i<length;i++){
		pkt->payload[i] = CipherText[i];
	}

	packetfunctions_tossFooter(pkt,pkt->l2_authenticationLength);

}

void decr_Transformation(uint8_t* cipherData,uint8_t length,
						 uint8_t authenticationLength,
						 unsigned long long int key){

	uint8_t i;
	for(i=0 ;i< 4; i++){
			U[i] = 0;
		}
	for(i=0 ;i< authenticationLength; i++){
		U[i] = cipherData[length-authenticationLength+i];
	}

	uint8_t newlen;
	newlen = length - authenticationLength;

	uint8_t CipherTextdec[130];//134-4 di authTag
	for(i=0;i<130;i++){
			CipherTextdec[i] = 0;
		}
	for(i=0;i<newlen;i++){
		CipherTextdec[i] = cipherData[i];
	}


	uint8_t count;
	count = 16-(newlen-((newlen/16)*16));

	for(i=newlen;i<count;i++){
		CipherTextdec[i] = 0;
	}

	//key expansion phase
	unsigned long long int newkey;
	newkey = key;
	for(i=0;i<8;i++){
			Key[i] = newkey;
			newkey = newkey >> 8;
		}

	KeyExpansion();

	Encr_Transformation(CipherTextdec,newlen,key,U,1);

	//parsing m|T

	for(i=0;i<newlen;i++){
		cipherData[i] = CipherText[i];//this will be the payload in plain text
	}

	for(i=0;i<authenticationLength;i++){
		T[i] = CipherText[newlen+i];
	}

}

bool auth_checking(uint8_t* ciphertext,uint8_t length,
		           unsigned long long int key){

	uint8_t messageDecr[128];
	uint8_t i;
	for(i=0;i<128;i++){
			messageDecr[i] = 0;
		}

	for(i=0;i<length-authlen;i++){
		messageDecr[i] = CipherText[i];
	}

	Input_Transformation(messageDecr,length);

	Auth_Transformation(length-authlen,key,1);

	for(i=0;i<4;i++){
		if(W[i] == MACTag[i]){
		}
		else{
			return FALSE;
		}
	}

	return TRUE;
}

//---------------------------------------------------------------------------
