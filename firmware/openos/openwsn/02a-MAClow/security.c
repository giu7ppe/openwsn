/**
\brief General Security Operations
*/



#include "security.h"

//=============================define==========================================

//=========================== variables =======================================

//=========================== prototypes ======================================

void security_SettingUpParameters();


//=========================== admin ===========================================

void security_init(){

	//Setting UP Phase
	security_SettingUpParameters();

	//Initialization of Frame Counter
	m_macFrameCounter = 0;

}

//=========================== public ==========================================

void security_outgoingFrame(OpenQueueEntry_t*   msg,
                            uint8_t             securityLevel,
                            uint8_t             keyIdMode,
                            open_addr_t*        keySource,
                            uint8_t          	keyIndex){

	uint8_t auxlen;
	uint8_t temp8b;
	uint8_t match;

	m_keyDescriptor* keypoint;

	if(m_macFrameCounter == (0xffffffffffffffff)){
		return;
	}

	//max length of MAC frames

	authLengthChecking(securityLevel); // length of auth
	msg->l2_authenticationLength = authlen;
	//auxLengthChecking(keyIdMode, auxlen); //length of Key ID field
	//for us, keyIdMode = 3 and so Auxlen = 9
	auxlen = 9;

	if((msg->length+auxlen+authlen+2) >= 130 ){ //2 bytes of CRC, 130 MaxPHYPacketSize
		return;
	}

	//check if SecurityLevel is not zero
	//in my impl. secLevel may not be zero if i'm here.
	/*if(securityLevel == ASH_SLF_TYPE_NOSEC){
		return;
	}*/

	open_addr_t* nextHop;
	nextHop = &msg->l2_nextORpreviousHop;

	//search for a key
	match = keyDescriptorLookup(keyIdMode,
								keySource,
								keyIndex,
								nextHop,
								//idmanager_getMyID(ADDR_PANID),
								msg->l2_frameType);

	keypoint = &MacKeyTable.KeyDescriptorElement[match];

	//start setting the Auxiliary Security Header
	temp8b = keyIndex; //key index field

	packetfunctions_reserveHeaderSize(msg, sizeof(uint8_t));
	*((uint8_t*)(msg->payload)) = temp8b;

	//Key Identifier Mode
	/*if(keyIdMode != 0){

		switch(keyIdMode){
		case(ASH_KIMF_TYPE_MACDEF):
		break;
		case(ASH_KIMF_TYPE_4OCTKEY):
			packetfunctions_writeAddress(msg, idmanager_getMyID(ADDR_16B) ,OW_LITTLE_ENDIAN);//da rivedere

		break;
		case(ASH_KIMF_TYPE_8OCTKEY):
			packetfunctions_writeAddress(msg,keySource,OW_LITTLE_ENDIAN);
		break;
		}
	}*/
	//in our impl. keyIdMode = 3
	packetfunctions_writeAddress(msg,keySource,OW_LITTLE_ENDIAN);

	//Frame Counter
	uint32_t temp;
	uint8_t i;
	temp = m_macFrameCounter;

	for(i=0;i<3;i++){
		packetfunctions_reserveHeaderSize(msg, sizeof(uint8_t));
		*((uint8_t*)(msg->payload)) = temp;
		temp = temp >>8;
	}

	packetfunctions_reserveHeaderSize(msg, sizeof(uint8_t));
	*((uint8_t*)(msg->payload)) = temp;


	//security control field
	packetfunctions_reserveHeaderSize(msg, sizeof(uint8_t));

	temp8b = 0;
	temp8b |= securityLevel << ASH_SCF_SECURITY_LEVEL;//3b
	temp8b |= keyIdMode << ASH_SCF_KEY_IDENTIFIER_MODE;//2b
	temp8b |= 0 << 3;//3b reserved
	*((uint8_t*)(msg->payload)) = temp8b;

	//cryptographic block
	for(i=0; i<8; i++){
		 nonce[i] = keySource->addr_64b[i];
	}

	temp = m_macFrameCounter;

	nonce[8] = temp;
	nonce[9] = temp << 8;
	nonce[10] = temp <<16;
	nonce[11] = temp <<24;
	nonce[12] = securityLevel;

//		CRYPTO TEST
//		asn_t init;
//
//		if(msg->l2_frameType == IEEE154_TYPE_DATA){
//
//		uint8_t start[5];
//
//		ieee154e_getAsn(start);
//
//		init.bytes0and1 = start[0]+256*start[1];
//		init.bytes2and3 = start[2]+256*start[3];
//		init.byte4 = start[4];
//		}


	//CCMstar(msg,keypoint->key);

//		if(msg->l2_frameType == IEEE154_TYPE_DATA){
//		uint16_t diff;
//		diff = ieee154e_asnDiff(&init);
//
//		openserial_printError(COMPONENT_RES,ERR_OK,
//							(errorparameter_t)diff,
//							(errorparameter_t)501);
//		}

	//h increment the Frame Counter and save.
	m_macFrameCounter++;

}

void retrieve_AuxiliarySecurityHeader(OpenQueueEntry_t*      msg,
                  	  	  	  	      ieee802154_header_iht* tempheader){

	//a check if security is enabled, for me it not useful. If I'm here, security is enabled.
//	if(tempheader->securityEnabled == TRUE){
//		msg->l2_security = IEEE154_SEC_YES_SECURITY;
//	}

//	if(msg->l2_security==FALSE){
//		return;
//	}

	uint8_t temp8b;

	//b check if 802.15.4 header is valid
	//if the header is not valid, I'm not here..

	//c retrieve the Security Control field
	//1byte, Security Control Field

	temp8b = *((uint8_t*)(msg->payload)+tempheader->headerLength);

	msg->l2_securityLevel = (temp8b >> ASH_SCF_SECURITY_LEVEL)& 0x07;//3b
	authLengthChecking(msg->l2_securityLevel);
	msg->l2_authenticationLength = authlen;

	/*if(securityLevel ==0){
		return;
	}*/

	//retrieve the KeyIdMode field
	msg->l2_keyIdMode = (temp8b >> ASH_SCF_KEY_IDENTIFIER_MODE)& 0x03;//2b

	tempheader->headerLength = tempheader->headerLength+1;

	//retrieve the FrameCounter field and control it is not in overflow

	//Frame Counter field, //l
	uint8_t temp,i;
	temp = 0;

	msg->l2_frameCounter = 0;
	for(i=0;i<3;i++){
		temp = *((uint8_t*)(msg->payload)+tempheader->headerLength);
		msg->l2_frameCounter |= temp;
		msg->l2_frameCounter = msg->l2_frameCounter <<8;
		tempheader->headerLength = tempheader->headerLength+1;
	}

	temp = *((uint8_t*)(msg->payload)+tempheader->headerLength);
	msg->l2_frameCounter |= temp;
	tempheader->headerLength = tempheader->headerLength+1;

	if(msg->l2_frameCounter == (0xffffffffffffffff)){
		return; // frame counter overflow
		}

   //retrieve the Key Identifier field
   //Key Identifier Field, variable length
   /*switch(keyIdMode){
	case (IEEE154_ADDR_NONE):
			break;
	case (IEEE154_ADDR_SHORT):
		packetfunctions_readAddress(
				((uint8_t*)(msg->payload)+tempheader->headerLength),
				ADDR_16B,
				&keySource,
				OW_LITTLE_ENDIAN);

				tempheader->headerLength = tempheader->headerLength+2;
	break;
	case(IEEE154_ADDR_EXT):
		packetfunctions_readAddress(
						((uint8_t*)(msg->payload)+tempheader->headerLength),
						ADDR_64B,
						&keySource,
						OW_LITTLE_ENDIAN);
		tempheader->headerLength = tempheader->headerLength+8;
	break;
	}*/

	//in our impl, keyIdMode = 3
	packetfunctions_readAddress(
						((uint8_t*)(msg->payload)+tempheader->headerLength),
						ADDR_64B,
						&msg->l2_keySource,
						OW_LITTLE_ENDIAN);

	tempheader->headerLength = tempheader->headerLength+8;

	temp8b = *((uint8_t*)(msg->payload)+tempheader->headerLength);

	msg->l2_keyIndex = (temp8b);
	tempheader->headerLength = tempheader->headerLength+1;

}

void security_incomingFrame(OpenQueueEntry_t*      msg){
	uint8_t match;

	//open_addr_t* panid;
	uint32_t tempfr;
	tempfr = m_macFrameCounter;

	//panid = &tempheader->panid;

	m_deviceDescriptor			*devpoint;
	m_keyDescriptor 			*keypoint;
	m_securityLevelDescriptor	*secLevel;

	//check that Security Level is not zero, impossible for me
	/*if(msg->securityLevel == ASH_SLF_TYPE_NOSEC){
		return;
	}*/

	//f key descriptor lookup

	match = keyDescriptorLookup(msg->l2_keyIdMode,
								&msg->l2_keySource,
								msg->l2_keyIndex,
								&msg->l2_nextORpreviousHop,
								//panid,
								msg->l2_frameType);

	keypoint = &MacKeyTable.KeyDescriptorElement[match];

	if(match == 25){
		msg->l2_toDiscard = TRUE;
		return;
	}

	//g device descriptor lookup

	open_addr_t Address;
	Address = msg->l2_nextORpreviousHop;
	if(msg->l2_keyIdMode == 0){
	  	if(neighbors_haveSomeChild() == TRUE){
	  		Address = *(idmanager_getMyID(ADDR_64B));
	  		}
	  }

	match = deviceDescriptorLookup(&Address,
						   	       //idmanager_getMyID(ADDR_PANID);
						   	   	   keypoint);


	devpoint = &MacDeviceTable.DeviceDescriptorEntry[match];

	//h Security Level lookup

	secLevel = securityLevelDescriptorLookup(msg->l2_frameType,
								  	  	  	 0,//msg->commandFrameIdentifier,
								  	  	  	 secLevel);


	//i+j+k

	if(incomingSecurityLevelChecking(secLevel,msg->l2_securityLevel,devpoint->Exempt)==FALSE){
		//return;
	}

	//l+m Anti-Replay



	if(msg->l2_frameCounter < devpoint->FrameCounter){
		msg->l2_toDiscard = TRUE;
	}

	//n Control of key used
	if(incomingKeyUsagePolicyChecking(keypoint,
									  msg->l2_frameType,
									  0
									  )  ==FALSE){
		//return; // improper key used
	}

	uint8_t i;
	for(i=0; i<8; i++){
		 nonce[i] = msg->l2_keySource.addr_64b[i];
	}

	uint32_t temp;
	temp = msg->l2_frameCounter;

	nonce[8] = temp;
	nonce[9] = temp << 8;
	nonce[10] = temp <<16;
	nonce[11] = temp <<24;
	nonce[12] = msg->l2_securityLevel;

	//CCMstarInverse(msg,keypoint->key);

	//q increment frame counter and save
	msg->l2_frameCounter +=1;

	//showing MACkeyTable content
	/*if(idmanager_getIsDAGroot() == TRUE){
		for(i=0;i<10;i++){
			openserial_printError(COMPONENT_RES,ERR_OK,
									(errorparameter_t)MacKeyTable.KeyDescriptorElement[i].key,
									(errorparameter_t)i);
		}
	}*/

	devpoint->FrameCounter = msg->l2_frameCounter;
	m_macFrameCounter = tempfr;

}

void authLengthChecking(uint8_t securityLevel){

	switch (securityLevel) {
	 case 0 :
		 authlen = 0;
		 break;
	 case 1 :
		 authlen = 4;
		 break;
	 case 2 :
		 authlen = 8;
	 		 break;
	 case 3 :
		 authlen = 16;
	 		 break;
	 case 4 :
		 authlen = 0;
	 		 break;
	 case 5 :
		 authlen = 4;
	 		 break;
	 case 6 :
		 authlen = 8;
	 		 break;
	 case 7 :
		 authlen = 16;
	 		 break;
	}

}

/*void auxLengthChecking(uint8_t KeyIdMode, uint8_t auxlen){

	//uint8_t auxlen;

	switch(KeyIdMode){
		case 0:
			auxlen = 0;
			break;
		case 1:
			auxlen = 1;
			break;
		case 2:
			auxlen = 5;
			break;
		case 3:
			auxlen = 9;
			break;
		default:
			openserial_printCritical(COMPONENT_IEEE802154,ERR_UNSUPPORTED_SECURITY,
				                                   (errorparameter_t)KeyIdMode,
				                                   (errorparameter_t)1);
			break;
	}

	//return auxlen;
}*/

bool incomingKeyUsagePolicyChecking(m_keyDescriptor* keydesc,
									uint8_t frameType,
									uint8_t cfi){

	uint8_t i;
	for(i=0; i<MAXNUMNEIGHBORS; i++){
		if (frameType != IEEE154_TYPE_CMD && frameType == keydesc->KeyUsageList[i].FrameType){
			return TRUE;
		}
//		commented to save ROM
//		if (frameType == IEEE154_TYPE_CMD && frameType == keydesc->KeyUsageList[i].FrameType && cfi == keydesc->KeyUsageList[i].CommandFrameIdentifier){
//			return TRUE;
//		}
	}

	return FALSE;
}

bool incomingSecurityLevelChecking(m_securityLevelDescriptor* seclevdesc,
								   uint8_t seclevel,
								   bool exempt){
	if (seclevdesc->AllowedSecurityLevels == 0){
		if(seclevel <= seclevdesc->SecurityMinimum){
			return TRUE;
		}
		else{
			return FALSE;
		}
	}

	if(seclevel <= seclevdesc->AllowedSecurityLevels){
		return TRUE;
	}

	if(seclevel == 0 && seclevdesc->DeviceOverrideSecurityMinimum ==TRUE ){
		if(exempt == FALSE){
							return FALSE;
		}

		return TRUE;
	}

	return FALSE;
}

m_securityLevelDescriptor* securityLevelDescriptorLookup( uint8_t frameType,
									uint8_t cfi,
									m_securityLevelDescriptor* answer){

	uint8_t i;
	for(i=0; i<4; i++){

		if(MacSecurityLevelTable.SecurityDescriptorEntry[i].FrameType != IEEE154_TYPE_CMD
			&& frameType == MacSecurityLevelTable.SecurityDescriptorEntry[i].FrameType){

			answer = &MacSecurityLevelTable.SecurityDescriptorEntry[i];

			return answer;
		}
//		commented to save ROM
//		if(MacSecurityLevelTable.SecurityDescriptorEntry[i].FrameType == IEEE154_TYPE_CMD
//			&& frameType == MacSecurityLevelTable.SecurityDescriptorEntry[i].FrameType
//			&& cfi == MacSecurityLevelTable.SecurityDescriptorEntry[i].CommandFrameIdentifier)
//		{
//
//			answer = &MacSecurityLevelTable.SecurityDescriptorEntry[i];
//			return answer;
//		}
	}

	return answer;
}

uint8_t deviceDescriptorLookup(open_addr_t* Address,
							   //open_addr_t* PANId,
							   m_keyDescriptor* keydescr){


	//commented to save ROM
	/*open_addr_t* aux;
	if(Address->type == IEEE154_ADDR_NONE){ //vado a prendere PANID, ShortAddress o Extended Address dal coordinator

		Address->type = ADDR_PANID;
		memcpy(Address->panid, (idmanager_getMyID(ADDR_PANID)->panid),sizeof(uint8_t)*2);
	}

	aux->addr_16b[1] = 255 ;
	aux->addr_16b[0] = 254 ;
	if(Address->type == IEEE154_ADDR_NONE && idmanager_getMyID(ADDR_16B) == aux){//questo significa che il dispositivo sta usando solo il suo extended address
		Address->type = ADDR_64B;
		memcpy(Address->addr_64b,(idmanager_getMyID(ADDR_64B)->addr_64b),sizeof(uint8_t)*8);
	}

	else{
		aux->addr_16b[1] = 255 ;
		aux->addr_16b[0] = 255 ;
		if(Address->type == IEEE154_ADDR_NONE && idmanager_getMyID(ADDR_16B) == aux){
			return answer;
		}
	}*/

	uint8_t i;

	for(i=0; i<MAXNUMNEIGHBORS; i++){

		if(packetfunctions_sameAddress(Address,keydescr->DeviceTable->DeviceDescriptorEntry[i].deviceAddress)== TRUE){
			return i;
		}
	}

	//return 25;
}

uint8_t keyDescriptorLookup(uint8_t  		KeyIdMode,
					     	open_addr_t*	keySource,
						 	uint8_t 		KeyIndex,
						 	open_addr_t* 	DeviceAddress,
						 	//open_addr_t*	panID,
						 	uint8_t			frameType){

	uint8_t i;

	if(KeyIdMode == 0){
		if(neighbors_haveSomeChild() == TRUE){
			DeviceAddress = idmanager_getMyID(ADDR_64B);
		}else{
			DeviceAddress = keySource;
		}

		for(i=0; i<MAXNUMKEYS; i++ ){
			if(packetfunctions_sameAddress(DeviceAddress,MacKeyTable.KeyDescriptorElement[i].KeyIdLookupList.Address)){
				//match = i;
				return i;
			}
		}

	}

	//commented to SAVE ROM
	/*uint8_t j;
	if (KeyIdMode == 1){


		for(i=0; i<MAXNUMKEYS; i++ ){
			uint8_t j;
			for(j=0; j<MAXNUMNEIGHBORS; j++){

				if(KeyIndex == macKeyTab.KeyDescriptorElement[i].KeyIdLookupList.KeyIndex
							&& packetfunctions_sameAddress(keySource,macDefaultKeySource)){
							return i;
						}
					}
			}
	}*/

	if (KeyIdMode == 3){//even if KeyIdMode == 2, we not explicite this condition to save ROM

		for(i=0; i<MAXNUMKEYS; i++ ){
				if(KeyIndex == MacKeyTable.KeyDescriptorElement[i].KeyIdLookupList.KeyIndex){

				if( packetfunctions_sameAddress(keySource,MacKeyTable.KeyDescriptorElement[i].KeyIdLookupList.KeySource)
						//&& packetfunctions_sameAddress(panID, macKeyTab.KeyDescriptorElement[i].KeyIdLookupList.PANId)
						){
				return i;
				}

			}
		}
	}

	return 25;//no matches

}


//=========================== private =========================================

void security_SettingUpParameters(){

	//MASTER KEY
	M_k = 249956789;

	//Initialization of Nonce String
	uint8_t i;
	for(i=0;i<13;i++){
		nonce[i] = 0;
	}

	//Initialization of the MAC Security Level Table
	for(i=0; i<2; i++){
		MacSecurityLevelTable.SecurityDescriptorEntry[i].FrameType = i;
		MacSecurityLevelTable.SecurityDescriptorEntry[i].CommandFrameIdentifier = 0;
		MacSecurityLevelTable.SecurityDescriptorEntry[i].DeviceOverrideSecurityMinimum = FALSE;
		MacSecurityLevelTable.SecurityDescriptorEntry[i].AllowedSecurityLevels = 7;
		MacSecurityLevelTable.SecurityDescriptorEntry[i].SecurityMinimum = 7;
	}

	//Initialization of MAC KEY TABLE
	for(i=0; i<MAXNUMKEYS;i++){
		MacKeyTable.KeyDescriptorElement[i].key = 0;
	}

	//Initialization of MAC DEVICE TABLE
	uint8_t j;
		for(i=0; i<MAXNUMNEIGHBORS; i++){
			for(j=0;j<8;j++){
				MacDeviceTable.DeviceDescriptorEntry[i].deviceAddress.addr_64b[j] = 0;
			}
		}

}

/*
 * Bootstrap Phase for the Parent Node
 */

void coordinator_init(){

	open_addr_t*  my;
	my = idmanager_getMyID(ADDR_64B);

	//Creation of the KeyDescriptor

	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeyIdMode = 3;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeyIndex = 1;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeySource = *(my);
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.Address = *(my);
	//macKeyTab.KeyDescriptorElement[0].KeyIdLookupList.PANId = *(idmanager_getMyID(ADDR_PANID));

	MacKeyTable.KeyDescriptorElement[0].KeyUsageList[1].FrameType = IEEE154_TYPE_DATA;
	MacKeyTable.KeyDescriptorElement[0].key = M_k;

	MacDeviceTable.DeviceDescriptorEntry[0].deviceAddress = *(my);
	MacDeviceTable.DeviceDescriptorEntry[0].FrameCounter = 0;

	MacKeyTable.KeyDescriptorElement[0].DeviceTable = &MacDeviceTable;

	openserial_printError(COMPONENT_RES,ERR_OK,
						(errorparameter_t)M_k,
						(errorparameter_t)102);

}

void remote_init(ieee802154_header_iht ieee802514_header){

	open_addr_t* src;
	//open_addr_t* panid;

	src= &ieee802514_header.src;

	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeyIdMode = 3;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeySource = *(src);
	//MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.PANId = ieee802514_header.panid;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeyIndex = 1;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.Address = (ieee802514_header.src);

	MacKeyTable.KeyDescriptorElement[0].KeyUsageList[1].FrameType = IEEE154_TYPE_DATA;


	MacKeyTable.KeyDescriptorElement[0].key = M_k;

	m_macDefaultKeySource = *(idmanager_getMyID(ADDR_16B));

	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.KeyIndex = 1;
	MacKeyTable.KeyDescriptorElement[0].KeyIdLookupList.Address = *(src);

	//DEVICE TABLE

	MacDeviceTable.DeviceDescriptorEntry[0].deviceAddress = *(src);
	MacDeviceTable.DeviceDescriptorEntry[0].FrameCounter = 0;

	MacKeyTable.KeyDescriptorElement[0].DeviceTable = &MacDeviceTable;

	openserial_printError(COMPONENT_RES,ERR_OK,
						(errorparameter_t)M_k,
						(errorparameter_t)201);

}
