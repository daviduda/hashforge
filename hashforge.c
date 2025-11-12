#define WIN32_LEAN_AND_MEAN
#include<windows.h>
#include<shellapi.h>
#include<wincred.h>
#include<bcrypt.h>
#include<locale.h>
#include<wchar.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "bcrypt.lib")

static BOOL WriteAll(HANDLE hFile, PUCHAR pbData, DWORD cbData) {
	DWORD cbWritten;
	while (cbData) {
		if (!WriteFile(hFile, pbData, cbData, &cbWritten, NULL)) {
			return TRUE;
		}
		cbData -= cbWritten;
		pbData += cbWritten;
	}
	return FALSE;
}

#define PRINT_ERROR(s) WriteAll(GetStdHandle(STD_ERROR_HANDLE), (PUCHAR)s, (DWORD)sizeof(s) - 1)

static void PrintErrorWin32(DWORD error) {
	PUCHAR pbMessage = NULL;
	DWORD cbMessage;
	cbMessage = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		error,
		0,
		(LPSTR)&pbMessage,
		0,
		NULL
	);
	if (cbMessage) {
		WriteAll(GetStdHandle(STD_ERROR_HANDLE), pbMessage, cbMessage);
	}
	LocalFree(pbMessage);
}

static void PrintErrorStatus(NTSTATUS status, LPCSTR src) {
	DWORD_PTR args[2] = { (DWORD_PTR)status, (DWORD_PTR)src };
	PUCHAR pbMessage = NULL;
	DWORD cbMessage;
	cbMessage = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		"`%2!s!` failed with NTSTATUS 0x%1!08X!\n",
		0,
		0,
		(LPSTR)&pbMessage,
		0,
		(va_list*)args
	);
	if (cbMessage) {
		WriteAll(GetStdHandle(STD_ERROR_HANDLE), pbMessage, cbMessage);
	}
	LocalFree(pbMessage);
}

static UCHAR ParseSpec(LPCWSTR spec, PUCHAR pbChars) {
	UINT32 charset[3] = { 0, 0, 0 };
	WCHAR lo, hi;
	UCHAR loblk, lobit, hiblk, hibit;
	UCHAR cbChars = 0;
	lo = *spec;
	if (lo == L'\\') {
		lo = *++spec;
	}
	if (lo < L'!' || lo > L'~') {
		return 0;
	}
	lo -= L'!';
	charset[lo >> 5] |= 1ul << (lo & 0x1F);
	hi = *++spec;
	while (hi) {
		if (hi == L'-') {
			hi = *++spec;
			if (hi == L'-') {
				hi = L'-' - L'!';
				charset[hi >> 5] |= 1ul << (hi & 0x1F);
				hi = *++spec;
			}
			while (hi == L'-') {
				hi = *++spec;
			}
			if (hi == L'\0') {
				lo = L'-' - L'!';
				charset[lo >> 5] |= 1ul << (lo & 0x1F);
				break;
			}
			if (hi == L'\\') {
				hi = *++spec;
			}
			if (hi < L'!' || hi > L'~') {
				return 0;
			}
			hi -= L'!';
			if (lo > hi) {
				return 0;
			}
			loblk = (UCHAR)lo >> 5;
			hiblk = (UCHAR)hi >> 5;
			lobit = (UCHAR)lo & 0x1F;
			hibit = (UCHAR)hi & 0x1F;
			if (loblk == hiblk) {
				hibit -= lobit - 1;
				charset[loblk] |= (hibit == 64) ? ~0ul : ((1ul << hibit) - 1) << lobit;
			}
			else {
				charset[loblk] |= ~0ul << lobit;
				charset[1] |= -((loblk == 0) & (hiblk == 2));
				charset[hiblk] |= (hibit == 63) ? ~0ul : (1ul << (hibit + 1)) - 1;
			}
			lo = hi;
		}
		else {
			if (hi == L'\\') {
				hi = *++spec;
			}
			if (hi < L'!' || hi > L'~') {
				return 0;
			}
			lo = hi - L'!';
			charset[lo >> 5] |= 1ul << (lo & 0x1F);
		}
		hi = *++spec;
	}
	hibit = 94;
	do {
		--hibit;
		if (charset[hibit >> 5] & (1ul << (hibit & 0x1F))) {
			pbChars[cbChars++] = hibit + '!';
		}
	} while (hibit);
	return cbChars;
}

int main(void) {
	UCHAR pbData[64];
	UCHAR pbChars[94];
	WCHAR username[CREDUI_MAX_USERNAME_LENGTH + 1] = L"";
	WCHAR password[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	DWORD error;
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hHash = NULL;
	HANDLE hOut;
	ULONG cbData, n;
	UCHAR cbChars, i, k, x;
	int argc;
	LPWSTR* argv = NULL;
	_locale_t locale;
	locale = _wcreate_locale(LC_ALL, L"C");
	if (!locale) {
		PRINT_ERROR("failed to create locale.\n");
		goto cleanup;
	}
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == NULL) {
		PrintErrorWin32(GetLastError());
		goto cleanup;
	}
	if (argc != 3) {
		PRINT_ERROR(
			"USAGE: hashforge <length> <chars>\n\n"
			"hasforge is a command-line password manager that derives a strong password from credentials.\n"
			"the user is prompted for credentials and a key is generated (same credentials = same key).\n"
			"the key is then formatted into a password using the command line arguments:\n"
			" - <length>: number of characters.\n"
			" - <chars> : allowed characters.\n"
			"example: `hashforge 16 \"a-zA-Z0-9!@#\"`.\n\n"
			"you can add single characters and ranges of characters in the <chars> string.\n"
			"only printable ASCII characters are allowed (except space).\n"
			"most characters simply represent themselves.\n"
			"the notation \"a-b\" represents all characters within the range (\"b\" must collate after \"a\").\n"
			"a backslash followed by any character represents that character.\n"
			"it is an error if no character follows an unescaped backslash\n\n"
			"ATTRIBUTIONS:\nthis project is heavily inspired by gnu-pw-mgr (but not nearly as good).\n"
			"the rules of <chars> are a minimal version of the rules of GNU `tr` strings.\n"
		);
		goto cleanup;
	}
	n = _wcstoul_l(argv[1], NULL, 0, locale);
	if (n == 0 || n == (ULONG)-1) {
		PRINT_ERROR("ERROR: <length> is not recognized as a valid number.\n");
		goto cleanup;
	}
	cbChars = ParseSpec(argv[2], pbChars);
	if (cbChars == 0) {
		PRINT_ERROR(
			"ERROR: <chars> is not valid.\n\n"
			"one of these events occured:\n"
			" - no character was found.\n"
			" - a space or a non-printable character was found.\n"
			" - a bad range (like \"b-a\") was found.\n"
			" - the last character is an unescaped backslash.\n"
		);
		goto cleanup;
	}
	error = CredUICmdLinePromptForCredentialsW(
		L"hashforge",
		NULL,
		0,
		username,
		ARRAYSIZE(username),
		password,
		ARRAYSIZE(password),
		NULL,
		CREDUI_FLAGS_EXCLUDE_CERTIFICATES | CREDUI_FLAGS_DO_NOT_PERSIST
	);
	if (error) {
		PrintErrorWin32(error);
		goto cleanup;
	}
	status = BCryptCreateHash(BCRYPT_CSHAKE256_ALG_HANDLE, &hHash, NULL, 0, NULL, 0, 0);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptCreateHash");
		goto cleanup;
	}
	status = BCryptSetProperty(hHash, BCRYPT_FUNCTION_NAME_STRING, (PUCHAR)L"KDF", sizeof(L"KDF"), 0);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptSetProperty");
		goto cleanup;
	}
	status = BCryptSetProperty(hHash, BCRYPT_CUSTOMIZATION_STRING, (PUCHAR)username, (ULONG)wcslen(username) * sizeof(WCHAR) + sizeof(WCHAR), 0);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptSetProperty");
		goto cleanup;
	}
	status = BCryptHashData(hHash, (PUCHAR)password, (ULONG)wcslen(password) * sizeof(WCHAR), 0);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptHashData");
		goto cleanup;
	}
	SecureZeroMemory(username, sizeof(username));
	SecureZeroMemory(password, sizeof(password));
	hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	k = (UCHAR)(256 / cbChars) * cbChars;
	while (n) {
		status = BCryptFinishHash(hHash, pbData, 64, BCRYPT_HASH_DONT_RESET_FLAG);
		if (!BCRYPT_SUCCESS(status)) {
			PrintErrorStatus(status, "BCryptFinishHash");
			goto cleanup;
		}
		cbData = 0;
		for (i = 0; i < 64; i++) {
			x = pbData[i];
			if (x < k) {
				pbData[cbData++] = pbChars[x % cbChars];
			}
		}
		cbData = (cbData < n) ? cbData : n;
		if (cbData && WriteAll(hOut, pbData, cbData)) {
			PrintErrorWin32(GetLastError());
			goto cleanup;
		}
		n -= cbData;
	}
	BCryptDestroyHash(hHash);
	LocalFree(argv);
	_free_locale(locale);
	return 0;
cleanup:
	SecureZeroMemory(username, sizeof(username));
	SecureZeroMemory(password, sizeof(password));
	if (hHash) {
		BCryptDestroyHash(hHash);
	}
	LocalFree(argv);
	_free_locale(locale);
	return 1;
}
