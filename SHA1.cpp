

#include "stdafx.h"
#include "SHA1.h"



inline uint32_t SHA1::SHA1CircularShift(uint8_t bits, uint32_t word)
{
	return (((word) << (bits)) | ((word) >> (32 - (bits))));
}

void SHA1::appendtoMessage_Block(const uint8_t * msg, unsigned int x)
{
	for(auto it=context.Message_Block.begin();it!=context.Message_Block.begin()+x;it++)
		*it = (*(msg++) & 0xFF); //ensures that inputted data to block is valid 8bit value
}

SHA1::SHA1()
{
	try {
		if (SHA1Reset() != SHA1::SHA_state::shaSuccess)
			throw std::bad_exception(); //throw exception when unable to perform SHA1Reset();
	}
	catch (...) {
		try {
			throw;
		}
		catch (const std::exception &ex) {
			std::cerr << ex.what();
			throw;
		}
		catch (...) {
			std::cerr << "unknown exception type";
			throw;
		}
			
	}

}


SHA1::~SHA1()
{
}




SHA1::SHA_state SHA1::SHA1Reset()
{

		//Set context to starting values
		context.Length_Low = 0;
		context.Length_High = 0;
		context.Message_Block_Index = 0;

		context.Intermediate_Hash[0] = 0x67452301;
		context.Intermediate_Hash[1] = 0xEFCDAB89;
		context.Intermediate_Hash[2] = 0x98BADCFE;
		context.Intermediate_Hash[3] = 0x10325476;
		context.Intermediate_Hash[4] = 0xC3D2E1F0;

		context.Computed = false;
		context.Corrupted = false;

	return shaSuccess;
}

SHA1::SHA_state SHA1::SHA1Input( const uint8_t *message_array, unsigned int length)
{
	if (!length)
	{
		return shaSuccess;
	}

	if (!message_array)
	{
		return shaNull;
	}

	if (context.Computed)
	{
		context.Corrupted = true;

		return shaStateError;
	}

	if (context.Corrupted)
	{
		return shaCorrupted;
	}


	const uint8_t* msg_ptr = nullptr;
	msg_ptr= message_array; //copy pointer


	while (length && !context.Corrupted)
	{
		//TODO rewrite this to check if at least 64 chars are avaiable, post themto message_block, increase Length_Low and High, check for overflow.
		//if there is less than 64chars then post the rest, set the flag computed to false. 
		//check length % 64 before doing anything then loop length/64 times the function.
		//check wat &oxFF is supposed to do when you parse 8bit variables. Is it about C++ and chars can be at least 8 bit ?


		/*
			While loop decrementing length parametr has been replaced with better loop, that performs less operations
		*/
		
		

		if (length>=64)
		{
			context.Length_Low += 512; //to be digested block size
			context.Message_Block_Index = 64;
			appendtoMessage_Block(msg_ptr); //icrements msg_ptr pointer
			length -= 64;
		}
		else
		{
			context.Length_Low += 8 * length;
			context.Message_Block_Index = length;
			appendtoMessage_Block(msg_ptr, length);
			length -= length;
		}


		if (context.Length_Low == 0) //when it overflows
		{
			context.Length_High++;
			if (context.Length_High == 0)
			{
				/* Message is too long */
				context.Corrupted = true;
			}
		}

		if (context.Message_Block_Index == 64)
		{
			SHA1ProcessMessageBlock();
		}

		//message_array++;
		

	}

	return shaSuccess;
}

int SHA1::SHA1Result(uint8_t *Message_Digest)
{
	

	if (!Message_Digest)
	{
		return shaNull;
	}

	if (context.Corrupted)
	{
		std::cerr<<"Context status corrupted:"<< context.Corrupted;
	}

	if (!context.Computed)
	{
		SHA1PadMessage();
		for (auto it=context.Message_Block.begin();it!=context.Message_Block.end();++it)
		{
			/* message may be sensitive, clear it out */
			*it = 0;
		}
		context.Length_Low = 0;    /* and clear length */
		context.Length_High = 0;
		context.Computed = true;
	}

	for (int i = 0; i < SHA1HashSize; ++i)
	{
		Message_Digest[i] = context.Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
	}

	return shaSuccess;
}

void SHA1::init()
{

};

void SHA1::SHA1PadMessage()
{
	/*
	*  Check to see if the current message block is too small to hold
	*  the initial padding bits and length.  If so, we will pad the
	*  block, process it, and then continue padding into a second
	*  block.
	*/
	if (context.Message_Block_Index > 55)
	{
		context.Message_Block[context.Message_Block_Index++] = 0x80;
		while (context.Message_Block_Index < 64)
		{
			context.Message_Block[context.Message_Block_Index++] = 0;
		}

		SHA1ProcessMessageBlock();

		while (context.Message_Block_Index < 56)
		{
			context.Message_Block[context.Message_Block_Index++] = 0;
		}
	}
	else
	{
		context.Message_Block[context.Message_Block_Index++] = 0x80;
		while (context.Message_Block_Index < 56)
		{
			context.Message_Block[context.Message_Block_Index++] = 0;
		}
	}

	/*
	*  Store the message length as the last 8 * 8-bits (octets)
	*/
	context.Message_Block[56] = context.Length_High >> 24;
	context.Message_Block[57] = context.Length_High >> 16;
	context.Message_Block[58] = context.Length_High >> 8;
	context.Message_Block[59] = context.Length_High;
	context.Message_Block[60] = context.Length_Low >> 24;
	context.Message_Block[61] = context.Length_Low >> 16;
	context.Message_Block[62] = context.Length_Low >> 8;
	context.Message_Block[63] = context.Length_Low;

	SHA1ProcessMessageBlock();
}

void SHA1::SHA1ProcessMessageBlock()
{

	uint32_t      temp;              /* Temporary word value        */
	uint32_t      A, B, C, D, E;     /* Word buffers                */

									 /*
									 *  Initialize the first 16 words in the array W
									 */
	for (int t = 0; t < 16; t++)
	{
		W[t] = context.Message_Block[t * 4] << 24;
		W[t] |= context.Message_Block[t * 4 + 1] << 16;
		W[t] |= context.Message_Block[t * 4 + 2] << 8;
		W[t] |= context.Message_Block[t * 4 + 3];
	}

	for (int t = 16; t < 80; t++)
	{
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = context.Intermediate_Hash[0];
	B = context.Intermediate_Hash[1];
	C = context.Intermediate_Hash[2];
	D = context.Intermediate_Hash[3];
	E = context.Intermediate_Hash[4];

	for (int t = 0; t < 20; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | ((~B) & D)) + E + W[t] + K[0];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);

		B = A;
		A = temp;
	}


	for (int t = 20; t < 40; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 40; t < 60; t++)
	{
		temp = SHA1CircularShift(5, A) +
			((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (int t = 60; t < 80; t++)
	{
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context.Intermediate_Hash[0] += A;
	context.Intermediate_Hash[1] += B;
	context.Intermediate_Hash[2] += C;
	context.Intermediate_Hash[3] += D;
	context.Intermediate_Hash[4] += E;

	context.Message_Block_Index = 0;
	
}



std::string sha1calc(const char * input)
{
	uint8_t msg_digest[SHA1HashSize];
	SHA1 obj;
	obj.SHA1Reset();
	//std::cout << "input=" << input << " len=" << strlen(input) << std::endl;
	obj.SHA1Input((uint8_t*)input, strlen(input)); //temp -1 due to null-terminator
	obj.SHA1Result(msg_digest);

	std::stringstream ss;
	//ss << std::setfill('0');
	/*for (int i = 0; i < SHA1HashSize; ++i)
		ss << std::hex << (unsigned int)msg_digest[i];*/
	return ss.str();

}
