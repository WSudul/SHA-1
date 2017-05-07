//SHA-1 implementation
//
#include "stdafx.h"
#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"

#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b
char *testarray[4] =
{
	TEST1,
	TEST2,
	TEST3,
	TEST4
};
long int repeatcount[4] = { 1, 1, 1000000, 10 };
char *resultarray[4] =
{
	"A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
	"84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
	"34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
	"DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52"
};



#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <chrono>

/*
*  Define patterns for testing
*/
#include "SHA1.h"
#include <iostream>
int main()
{
	//std::string d = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
	//128 bit char*
	std::string d = "abc123ed";
	std::chrono::high_resolution_clock::time_point start, end, start2, end2;
	std::chrono::duration<double> elapsed_seconds, dur_fin;
	unsigned z;
	std::cin >> z;
	for (int j = 0; j < 1;j++) {
		start2 = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < z; i++)
		{
			
			//std::cout << d.length() << std::endl;
			start = std::chrono::high_resolution_clock::now();
			sha1calc(d.c_str());
			end = std::chrono::high_resolution_clock::now();
			elapsed_seconds = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
			std::cout << float(d.length()) / (1024.0) << "kB\t\t" << elapsed_seconds.count() <<" speed="<< d.length()/ elapsed_seconds.count()/1024/1024<< std::endl;
			d.append(d);
		}
		end2 = std::chrono::high_resolution_clock::now();
		dur_fin = std::chrono::duration_cast<std::chrono::milliseconds>(end2 - start2);
		std::cout <<"\toverall time:" << elapsed_seconds.count() << std::endl;
		//d = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaadddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
		d = "abc123";
	};
	std::cout << "end\n";
	
	return 0;
}

