#include "modAlphaCipher.h"

#include <UnitTest++/UnitTest++.h>
#include <codecvt>
#include <locale>
#include <string>
using namespace std;

wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> codec;
SUITE(KeyTest)
{
    TEST(ValidKey) { CHECK_EQUAL("АЯЯКАМДС", codec.to_bytes(modAlphaCipher(L"АСЯ").encrypt(L"АНАКОНДА"))); }
    TEST(LongKey) { CHECK_EQUAL("ПСМ", codec.to_bytes(modAlphaCipher(L"ПАНДЕМОНИУМ").encrypt(L"АСЯ"))); }
    TEST(LowCaseKey) { CHECK_EQUAL("АЯЯКАМДС", codec.to_bytes(modAlphaCipher(L"ася").encrypt(L"АНАКОНДА"))); }
    TEST(DigitsInKey) { CHECK_THROW(modAlphaCipher cp(L"АСЯ1"), cipher_error); }
    TEST(PunctuationInKey) { CHECK_THROW(modAlphaCipher cp(L"АС,Я"), cipher_error); }
    TEST(WhitespaceInKey) { CHECK_THROW(modAlphaCipher cp(L"A СЯ"), cipher_error); }
    TEST(EmptyKey) { CHECK_THROW(modAlphaCipher cp(L""), cipher_error); }
    TEST(WeakKey) { CHECK_THROW(modAlphaCipher cp(L"AAA"), cipher_error); }
}
struct KeyB_fixture {
    modAlphaCipher* p;
    KeyB_fixture() { p = new modAlphaCipher(L"Б"); }
    ~KeyB_fixture() { delete p; }
};
SUITE(EncryptTest)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString)
    {
        CHECK_EQUAL("ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ",
                    codec.to_bytes(p->encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString)
    {
        CHECK_EQUAL("ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ",
                    codec.to_bytes(p->encrypt(L"стальгрозитхолоднойсмертьюнамнепривыкатьрайманитпрекраснойтрельюужнедолгождать")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithWhitspaceAndPunct)
    {
        CHECK_EQUAL("ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ",
                    codec.to_bytes(p->encrypt(L"СТАЛЬ ГРОЗИТ ХОЛОДНОЙ СМЕРТЬЮ, НАМ НЕ ПРИВЫКАТЬ, РАЙ МАНИТ ПРЕКРАСНОЙ ТРЕЛЬЮ , УЖ НЕ ДОЛГО ЖДАТЬ")));
    }
    TEST_FIXTURE(KeyB_fixture, StringWithNumbers)
    {
        CHECK_EQUAL("ОБТГДСФРРЁШЁМПГЁЛ", codec.to_bytes(p->encrypt(L"НАС В ГРУППЕ 19 ЧЕЛОВЕК")));
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) { CHECK_THROW(p->encrypt(L""), cipher_error); }
    TEST_FIXTURE(KeyB_fixture, NoAlphaString) { CHECK_THROW(p->encrypt(L"1234+8765=9999"), cipher_error); }
    TEST(MaxShiftKey)
    {
        CHECK_EQUAL("РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ",
                    codec.to_bytes(modAlphaCipher(L"Я").encrypt(L"СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ")));
    }
}
SUITE(DecryptText)
{
    TEST_FIXTURE(KeyB_fixture, UpCaseString) {
        CHECK_EQUAL("СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ",
                    codec.to_bytes(p->decrypt(L"ТУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ")));
    }
    TEST_FIXTURE(KeyB_fixture, LowCaseString) {
        CHECK_THROW(p->decrypt(L"тУБМЭДСПИЙУЦПМПЕОПКТНЁСУЭЯОБНОЁРСЙГЬЛБУЭСБКНБОЙУРСЁЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, WhitespaceString) {
        CHECK_THROW(p->decrypt(L"ТУБМЭДСПИЙУЦ ПМПЕОПКТНЁСУЭ ЯОБНОЁРСЙГЬЛ БУЭСБ КНБОЙУРСЁЛСБТО ПКУСЁМЭЯ ФЗОЁЕП МДП ЗЕБУЭ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, DigitsString) {
        CHECK_THROW(p->decrypt(L"ТУМ212121212"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, PunctString) {
        CHECK_THROW(p->decrypt(L"ТУБМЭДСПИЙУЦПМП,УРСЁ,ЛСБТОПКУСЁМЭЯФЗОЁЕПМДПЗЕБУЭ"),cipher_error);
    }
    TEST_FIXTURE(KeyB_fixture, EmptyString) {
        CHECK_THROW(p->decrypt(L""),cipher_error);
    }
    TEST(MaxShiftKey) {
        CHECK_EQUAL("СТАЛЬГРОЗИТХОЛОДНОЙСМЕРТЬЮНАМНЕПРИВЫКАТЬРАЙМАНИТПРЕКРАСНОЙТРЕЛЬЮУЖНЕДОЛГОЖДАТЬ",
                    codec.to_bytes(modAlphaCipher(L"Я").decrypt(L"РСЯКЫВПНЖЗСФНКНГМНИРЛДПСЫЭМЯЛМДОПЗБЪЙЯСЫПЯИЛЯМЗСОПДЙПЯРМНИСПДКЫЭТЁМДГНКВНЁГЯСЫ")));
    }
}
int main()
{
    locale loc("ru_RU.UTF-8");
    locale::global(loc);
    return UnitTest::RunAllTests();
}
