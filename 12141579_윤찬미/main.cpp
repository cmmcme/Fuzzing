#include <Windows.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <ctime>
using namespace std;

wchar_t cmd[] = L"C:\\Users\\assist304\\Desktop\\Fuzzing\\mutate.avi";
const char forg[] = "C:\\Users\\assist304\\Desktop\\Fuzzing\\org.avi";
const char fmut[] = "C:\\Users\\assist304\\Desktop\\Fuzzing\\mutate.avi";

void ChunkSize(char *buf, const size_t bufsize, const size_t mutcount) {

	for (size_t i = 4; i< mutcount; i++)	// �������� ũ�⸦ ���δ�. ���̳ʽ��� �� ���� �����Ƿ� �̰��� fuzzing �� Ȯ���� ���ٰ� �����ߴ�..!
	{
		buf[i] = buf[i] - '\x01';
	}
}

void MaxPerSec(char *buf, const size_t bufsize, const size_t mutcount) {
	for (size_t i = 0x84; i< mutcount; i++)		// maxpersec �� ��� ��Ʈ�� 0���� ���� �ʴ� ���� ����Ʈ�� ���ְ� �Ͽ� ���� ��Ű�� ���ϰ��Ѵ�.
	{
		buf[i] = '\x00';
	}
}
void TotalFrame(char *buf, const size_t bufsize, const size_t mutcount) {

	for (size_t i = 0x90; i < mutcount; i++)
	{
		buf[i] = buf[i] / '\x03';	//��Ż �������� ������ ������Ų��. 
	}
}

int main() {
	cout << "RUN START" << endl;
	ifstream ifs(forg, ios::binary | ios::in);
	ofstream ofs(fmut, ios::binary | ios::out | ios::trunc);
	if (!ifs | !ofs) {
		if (!ifs) cerr << forg << " not found!" << endl;
		if (!ofs) cerr << fmut << " not found!" << endl;
	}
	ifs.seekg(0, ifs.end);
	size_t flen = ifs.tellg();
	ifs.seekg(0);
	const size_t bufsize = 1024;
	char buf[bufsize] = "";
	const size_t chunksizebyte = 0x08;	// chunksize�� 0x04���� 4����Ʈ �̹Ƿ� 0x08�����̴�.
	const size_t MPSbyte = 0x88;		// MaxPersecbyte �� 0x80 ���� 4����Ʈ��  MicroSecPerFrame �� �ڿ� ��ġ�� 4����Ʈ �̴�.
	const size_t Total = 0x94;			// 4����Ʈ ũ�⸦ ������ 4���� ���� ���� �Ŀ� ��ġ�� TotalFrame �� ������ ��ġ�� 0x93 �̱⿡ 0x94�� ����
	srand(time(NULL));
	ifs.read(buf, flen % bufsize);	// avi������ ������ �о� ���δ�.

									// buf�� ���� �ٲ��ش�.
	ChunkSize(buf, flen%bufsize, chunksizebyte);	// mutate �Ѵ�.
	MaxPerSec(buf, flen%bufsize, MPSbyte);	// mutate �Ѵ�.
	TotalFrame(buf, flen%bufsize, Total);	// mutate �Ѵ�.

	ofs.write(buf, flen%bufsize);

	// mutate�� buf�� mut.avi ���Ͽ� �ٽ� ����.
	while (ifs.read(buf, bufsize))
	{
		ChunkSize(buf, flen%bufsize, chunksizebyte);
		MaxPerSec(buf, flen%bufsize, MPSbyte);
		TotalFrame(buf, flen%bufsize, Total);
		ofs.write(buf, flen%bufsize);

	}
	ifs.close();
	ofs.close();


	if ((int)ShellExecute(NULL, TEXT("open"), cmd, NULL, NULL, SW_SHOW) < 32)
		exit(0);
	/* CreateProcess�� ������ ���� ������ ShellExecute �� ����Ͽ���. 32��Ʈ �̱� ������ 32���� ������ ������ ����.
	cmd ��ġ�� ������ open �Ѵ�.

	*/

	return 0;
}