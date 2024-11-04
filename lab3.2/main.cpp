#include "modTableCipher.h"
#include <UnitTest++/UnitTest++.h>
#include <iostream>
#include <limits>
#include <locale>
#include <string>
#include <codecvt>


using namespace std;
wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) {
        CHECK_EQUAL("ЛА*АРТВОН", codec.to_bytes((TableCipher(L"3").encrypt(L"ВАЛОРАНТ"))));
    }
    TEST(NegativeKey) {
        CHECK_THROW(TableCipher cp(L"-5"),cipher_error);
    }
    TEST(WhitespaceInKey) {
        CHECK_THROW(TableCipher cp(L"10 0"),cipher_error);
    }
    TEST(EmptyKey) {
        CHECK_THROW(TableCipher cp(L""),cipher_error);
    }
    TEST(NotNumbers) {
        CHECK_THROW(TableCipher cp(L"ПРивет1,"),cipher_error);
    }
	TEST(TheKeyExceedsHalfTheText) {
	    TableCipher cp(L"5");
        CHECK_THROW(cp.encrypt(L"ВАЛОРАНТ"),cipher_error);
    }
}

struct KeyB_fixture {
    TableCipher * p;
    KeyB_fixture()
    {
        p = new TableCipher(L"3");
    }
    ~KeyB_fixture()
    {
        delete p;
    }
};

SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ЛА*АРТВОН",
                    codec.to_bytes(p->encrypt(L"ВАЛОРАНТ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_EQUAL("ЛА*АРТВОН",
                    codec.to_bytes(p->encrypt(L"валорант")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct) {
        CHECK_EQUAL("****АОАТВЛРН",
                    codec.to_bytes(p->encrypt(L"ВА! ЛО! РА! НТ!")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers) {
        CHECK_EQUAL("ЛА*АРТВОН", codec.to_bytes(p->encrypt(L"ВАЛОРАНТ1232323")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->encrypt(L""),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) {
        CHECK_THROW(p->encrypt(L"1676765545454"),cipher_error);
    }
}

SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("ВАЛОРАНТ",
                    codec.to_bytes(p->decrypt(L"ЛА*АРТВОН")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"ЛА*АРтвон"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"Л А*А Р т во н"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"Л1А*АРТ1ВОН"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"ЛА*,,,,,Ртвон"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
}


int main(int argc, char **argv)
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
