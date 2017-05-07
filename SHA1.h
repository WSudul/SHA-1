#pragma once

/*
f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)

f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)

f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)

f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79).

A sequence of constant words K(0), K(1), ... , K(79) is used in the
SHA-1.  In hex these are given by

K(t) = 5A827999         ( 0 <= t <= 19)

K(t) = 6ED9EBA1         (20 <= t <= 39)

K(t) = 8F1BBCDC         (40 <= t <= 59)

K(t) = CA62C1D6         (60 <= t <= 79).



*/

#define SHA1HashSize 20

#include <cstdint>
#include "iostream"
#include <sstream>
#include <array>
#include <string>
#include <iomanip>
#include <stdexcept>
#include <iterator>



/*!
	SHA-1 Implementation based on RFC 3174
	https://tools.ietf.org/html/rfc3174
	SHA-1 is a message digest function.
	It creates a 160-bit output 
	The maximum input message is 2^64 bits (limited by alghoritm designed)
	
	The following implementation is designed for creating object that performs the digest
	and returns it via provided addititonal method. The result itself is stored temporarily in the method, so no trace remains inside object.
	The goal of not using static methods and members is to provide possibility of multithreading when using this object

*/
class SHA1
{

private:

	struct SHA1Context
	{
		uint32_t Intermediate_Hash[SHA1HashSize / 4]; /*! Message Digest  */

		uint32_t Length_Low;            /*! Message length in bits */
		uint32_t Length_High;           /*! Message length in bits */			
		int_least16_t Message_Block_Index;/*! Index into message block array  */
		std::array<uint8_t, 64> Message_Block;      /*! 512-bit message blocks  */


		bool Computed;               /*! Is the digest computed?         */
		bool Corrupted;             /*! Is the message digest corrupted? */
	};

	inline void appendtoMessage_Block(const uint8_t* msg, unsigned int x = 64 ); /* appends x bits to Message_Block from buffer msg*/


	/*!
		table K with constant values for processing hash
	*/
	const std::array<uint32_t,4> K = { 
		0x5A827999,
		0x6ED9EBA1,
		0x8F1BBCDC,
		0xCA62C1D6
	};

	std::array<uint32_t, 80>W; /*! Word sequence used by SHA1ProcessMessageBlock(). Needs to be wiped for security */


	/*!
	Struct storing internal state of ongoing calculations
	Needs to be reset after usage (or prior new usage)
	*/
	SHA1Context context;

	enum SHA_state {
		shaSuccess = 0,
		shaNull,			//Null pointer param
		shaInputTooLong,	//input data too long
		shaStateError,		//called Input after Result
		shaCorrupted		//Digest is corrupted
	};



public:
	/*! default ctor*/
	SHA1();
	/*! default dtor*/
	~SHA1();

	//void sha1calc(char *input);

	/*!
		Reseting the SHA1Context context struct
	*/
	SHA1::SHA_state SHA1Reset();
	
	/*!
		Accept array of octests as the next portion of the msg
		Context gets updated, array of chars representing the next portion of msg is needed
		length - length if message is msg_arr
	*/
	SHA1::SHA_state SHA1Input( const uint8_t *message_array,unsigned int length);
	/*!
		Returns the 160-bit digest to Message_Digest
	*/
	int SHA1Result(uint8_t *Message_Digest);

	void init();

	
	/*!padding to even 512bits,first bit will be '1' */
	inline void SHA1PadMessage();
	/*!process next 512bits of msg stored in msg_block array */
	inline void SHA1ProcessMessageBlock();
	/*! shifting 32-bit word */
	inline uint32_t SHA1CircularShift(uint8_t bits, uint32_t word);

};



std::string sha1calc(const char * input);