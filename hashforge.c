#define WIN32_LEAN_AND_MEAN
#include<windows.h>
#include<shellapi.h>
#include<wincred.h>
#include<bcrypt.h>
#include<wchar.h>

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "bcrypt.lib")

static WCHAR username[CREDUI_MAX_USERNAME_LENGTH + 1];
static WCHAR password[CREDUI_MAX_PASSWORD_LENGTH + 1];

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

static DWORD ParseUint(LPCWSTR n) {
	WCHAR b = 10, c, d;
	DWORD x = 0, cutoff, cutlim;
	c = *n;
	while (1) {
		switch (c) {
		case L' ':
		case L'\t':
		case L'\n':
		case L'\r':
		case L'\f':
		case L'\v':
			c = *++n;
			continue;
		case L'\0':
			return 0;
		}
		break;
	}
	if (c == L'0') {
		switch (c = *++n) {
		case L'x':
		case L'X':
			b = 16;
			c = *++n;
			break;
		case L'b':
		case L'B':
			b = 2;
			c = *++n;
			break;
		case L'\0':
			return 0;
		default:
			b = 8;
		}
	}
	cutoff = 0xFFFFFFFF / b;
	cutlim = 0xFFFFFFFF % b;
	while (1) {
		if (c >= L'0' && c <= L'9') {
			d = c - L'0';
		}
		else if (c >= L'a' && c <= L'z') {
			d = c - L'a' + 10;
		}
		else if (c >= L'A' && c <= L'Z') {
			d = c - L'A' + 10;
		}
		else {
			return c ? 0 : x;
		}
		if (d >= b || x > cutoff || (x == cutoff && d > cutlim)) {
			return 0;
		}
		x = x * b + d;
		c = *++n;
	}
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
	UCHAR key[64];
	UCHAR pbData[64];
	UCHAR pbChars[94];
	DWORD error;
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hHash = NULL;
	HANDLE hOut;
	DWORD cbData, n, i;
	UCHAR cbChars, j, k, x;
	int argc;
	LPWSTR* argv;
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == NULL) {
		PrintErrorWin32(GetLastError());
		goto cleanup;
	}
	if (argc != 3) {
		PRINT_ERROR(
			"USAGE: hashforge <length> <chars>\n\n"
			"`hasforge` is a command-line password manager that derives a strong password from credentials.\n"
			"The user is prompted for credentials and a key is generated (same credentials = same key).\n"
			"The key is then used to stream pseudorandom bytes which are formatted into a password using the command line arguments:\n"
			" - <length>: number of characters.\n"
			" - <chars> : allowed characters.\n\n"
			"Both single characters and ranges of characters can be added in the <chars> string.\n"
			"Only printable ASCII characters are allowed (except space).\n"
			"Most characters simply represent themselves.\n"
			"The notation \"a-b\" represents all characters within the range (\"b\" must collate after \"a\").\n"
			"A backslash followed by any character represents that character.\n"
			"It is an error if no character follows an unescaped backslash\n\n"
			"EXAMPLE: hashforge 16 \"a-zA-Z0-9!@#\"\n\n"
			"ATTRIBUTIONS:\nThis project is heavily inspired by gnu-pw-mgr (but not nearly as good).\n"
			"The rules of <chars> are a minimal version of the rules of GNU `tr` strings.\n"
		);
		goto cleanup;
	}
	n = ParseUint(argv[1]);
	if (n == 0) {
		PRINT_ERROR("ERROR: <length> is 0 not recognized as a valid number.\n");
		goto cleanup;
	}
	cbChars = ParseSpec(argv[2], pbChars);
	if (cbChars == 0) {
		PRINT_ERROR(
			"ERROR: <chars> is not valid.\n\n"
			"One of these events occured:\n"
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
	status = BCryptDeriveKeyPBKDF2(
		BCRYPT_HMAC_SHA512_ALG_HANDLE,
		(PUCHAR)password,
		sizeof(password),
		(PUCHAR)username,
		sizeof(username),
		100000,
		key,
		64,
		0
	);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptDeriveKeyPBKDF2");
		goto cleanup;
	}
	SecureZeroMemory(username, sizeof(username));
	SecureZeroMemory(password, sizeof(password));
	status = BCryptCreateHash(BCRYPT_HMAC_SHA512_ALG_HANDLE, &hHash, NULL, 0, key, 64, BCRYPT_HASH_REUSABLE_FLAG);
	if (!BCRYPT_SUCCESS(status)) {
		PrintErrorStatus(status, "BCryptCreateHash");
		goto cleanup;
	}
	hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	k = 256 - (256 % (UCHAR)cbChars);
	i = 0;
	while (n) {
		status = BCryptHashData(hHash, (PUCHAR)(&i), sizeof(i), 0);
		if (!BCRYPT_SUCCESS(status)) {
			PrintErrorStatus(status, "BCryptHashData");
			goto cleanup;
		}
		status = BCryptFinishHash(hHash, pbData, 64, 0);
		if (!BCRYPT_SUCCESS(status)) {
			PrintErrorStatus(status, "BCryptFinishHash");
			goto cleanup;
		}
		cbData = 0;
		for (j = 0; j < 64; j++) {
			x = pbData[j];
			if (x < k) {
				pbData[cbData++] = pbChars[x % cbChars];
			}
		}
		cbData = (cbData < n) ? cbData : n;
		if (cbData && WriteAll(hOut, pbData, cbData)) {
			PrintErrorWin32(GetLastError());
			goto cleanup;
		}
		++i;
		n -= cbData;
	}
	SecureZeroMemory(key, sizeof(key));
	SecureZeroMemory(pbData, sizeof(pbData));
	BCryptDestroyHash(hHash);
	LocalFree(argv);
	return 0;
cleanup:
	SecureZeroMemory(username, sizeof(username));
	SecureZeroMemory(password, sizeof(password));
	SecureZeroMemory(key, sizeof(key));
	SecureZeroMemory(pbData, sizeof(pbData));
	if (hHash) {
		BCryptDestroyHash(hHash);
	}
	LocalFree(argv);
	return 1;
}

/* Optional entry point */
void __stdcall entry(void) {
	UINT r = (UINT)main();
	ExitProcess(r);
}
