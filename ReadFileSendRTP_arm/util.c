/*
 * util.c
 *
 *  Created on: Jul 24, 2018
 *      Author: bruce
 */

#include "util.h"


int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	int rw,rwed;

	if((fp = fopen(filename, mode)) == NULL )
	{
		return 0;
	}
	rwed = 0;
	while((!feof(fp)) && (size > rwed))
	{
		if((rw = fread(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}
		rwed += rw;
	}
	fclose(fp);
	return rwed;
}

int FileReadValue(char *filename, char *value)
{
	FILE *fp;
	char cc;
	int i = 0;
	unsigned int rv;

	if((fp = fopen(filename, "r")) == NULL )
	{
		return 0;
	}

	rv = fread(&cc, 1, 1,fp);
	if(rv < 1)
		return 0;

	value[i++]=cc;

	while((!feof(fp)) && (cc > 32))
	{
		rv = fread(&cc, 1, 1,fp);
		if(rv < 1)
			break;

		value[i++]=cc;
	}

	value[i++]='\0';
	fclose(fp);
	return i;
}

int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	int rw,rwed;

	if((fp = fopen(filename, mode)) == NULL )
	{
		return 0;
	}
	rwed = 0;
	while(size > rwed)
	{
		if((rw = fwrite(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}
		rwed += rw;
	}
	fclose(fp);
	return rwed;
}


void GetAnyKey()
{
	int ch;

	while ( (ch=getchar()) != '\n' && ch != EOF )
	{
		;
	}

	return ;
}

int GetInputIndexZone(int *pIndex1, int *pIndex2, int nMin, int nMax)
{
	/*
#define OPT_EXIT        -1
#define OPT_RETURN        -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
	*/
	int ch;
	int index1 = 0;
	int index2 = 0;
	int uiFlag = 0;

	ch = GETCH();

	if((ch == 'e') || (ch == 'E') || (ch == 'q') || (ch == 'Q'))
	{
		/*[退出[E]]*/
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_EXIT;
	}
	else if((ch == 'n') || (ch == 'N') || (ch == 13) || (ch == 10))
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		*pIndex1 = nMin;
		*pIndex2 = nMin;

		return 0;
	}
	else if((ch == 'P') || (ch == 'p'))
	{
		/*有[上一步(P)]选项*/
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_PREVIOUS;
	}
	else if((ch == 'r') || (ch == 'R') || (ch == 'B') || (ch == 'b'))
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_RETURN;
	}
	else if((ch == 'c') || (ch == 'C') )
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_CANCEL;
	}

	while(1)
	{
		if((('0' <= ch) && (ch <= '9')) || ((ch == '-') && (index1 != 0)))
		{
			if((uiFlag == 0) && (ch == '-'))
			{
				uiFlag = 1;
			}

			if(uiFlag == 0)
			{
				index1 = index1 * 10 + (ch - '0');
			}

			if((uiFlag == 1) && (ch != '-'))
			{
				index2 = index2 * 10 + (ch - '0');
			}

			PUTCH(ch);

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
				break;
		}
		else
		{
			ch = GETCH();
			continue;
		}
	}

	if(index1  == 0)
	{
		*pIndex1 = nMin;
		*pIndex2 = nMin;
	}
	else
	{
		if(index2 <= index1)
		{
			if(index1 > nMax)
			{
				index1 = nMax;
			}

			if(index1 < nMin)
			{
				index1 = nMin;
			}

			*pIndex1 = index1;
			*pIndex2 = index1;
		}
		else
		{
			if(index2 < nMin)
			{
				index1 = nMin;
				index2 = nMin;
				*pIndex1 = index1;
				*pIndex2 = index2;
			}
			else if((index1 < nMin) && ((index2 >= nMin) && (index2 <= nMax)))
			{
				index1 = nMin;
				*pIndex1 = index1;
				*pIndex2 = index2;
			}
			else if(((index1 >= nMin) && (index1 <= nMax)) && (index2 > nMax))
			{
				index2 = nMax;
				*pIndex1 = index1;
				*pIndex2 = index2;
			}
			else if(index1 > nMax)
			{
				index1 = nMax;
				index2 = nMax;
				*pIndex1 = index1;
				*pIndex2 = index2;
			}
			else
			{
				*pIndex1 = index1;
				*pIndex2 = index2;
			}
		}
	}

	return 0;
}

int GetInputLength(int nDefaultLength, int nMin, int nMax)
{
	/*
#define OPT_EXIT        -1
#define OPT_RETURN        -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
	*/
	int len,ch;

	ch = GETCH();

	if((ch == 'e') || (ch == 'E') || (ch == 'q') || (ch == 'Q'))
	{
		/*[退出[E]]*/
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_EXIT;
	}
	else if((ch == 'n') || (ch == 'N') || (ch == 13) || (ch == 10))
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return nDefaultLength;
	}
	else if((ch == 'P') || (ch == 'p'))
	{
		/*有[上一步(P)]选项*/
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_PREVIOUS;
	}
	else if((ch == 'r') || (ch == 'R') || (ch == 'B') || (ch == 'b'))
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_RETURN;
	}
	else if((ch == 'c') || (ch == 'C') )
	{
		while((ch != 13) && (ch != 10))
			ch=GETCH();

		return OPT_CANCEL;
	}

	len = 0;
	while(1)
	{
		if((ch > '9') || (ch < '0'))
		{
			ch = GETCH();
			continue;
		}

		PUTCH(ch);
		len = len * 10 + (ch - '0');

		ch = GETCH();

		if((ch == '\n') || (ch == '\r'))
			break;
	}

	if(len  == 0)
	{
		if(nDefaultLength > 0)
		{
			len = nDefaultLength;
		}
		else
		{
			len = nMin;
		}
	}
	else if(len < nMin)
	{
		if(nDefaultLength > 0)
		{
			len = nDefaultLength;
		}
		else
		{
			len = nMin;
		}
	}
	else if(len > nMax)
	{
		if(nDefaultLength > 0)
		{
			len = nDefaultLength;
		}
		else
		{
			len = nMax;
		}
	}
	else
	{
		;
	}

	return len;
}

int GetPasswd(char *str, int maxSize)
{
	int res = 0;
	struct termios new_setting,init_setting;

	//get termios setting and save it
	tcgetattr(0,&init_setting);
	new_setting=init_setting;

	new_setting.c_lflag&=~ECHO;
	tcsetattr(0,TCSANOW,&new_setting);

	res = GetString(str, maxSize);

	//restore the setting
	tcsetattr(0,TCSANOW,&init_setting);
	printf("\n");
	return res;
}

int GetSelect(int nDefaultSelect, int nMaxSelect)
{
	/*
#define OPT_EXIT        -1
#define OPT_RETURN        -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
	*/
	int nSel,ch;
	while(1)
	{
		ch = GETCH();
#if 0
#ifdef WIN32
		putch(ch);
#endif
#endif
		if((ch == 'e') || (ch == 'E') || (ch == 'q') || (ch == 'Q'))
		{
			PUTCH(ch);

			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();
			/*[..[E]]*/
			return OPT_EXIT;
		}
		else if((ch == 'n') || (ch == 'N') || (ch == 13) || (ch == 10))
		{
			PUTCH(ch);

			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();

			return nDefaultSelect;
		}
		else if((ch == 'P') || (ch == 'p'))
		{
			PUTCH(ch);

			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();
			/*.[...(P)]..*/
			return OPT_PREVIOUS;
		}
		else if((ch == 'r') || (ch == 'R') || (ch == 'B') || (ch == 'b'))
		{
			PUTCH(ch);

			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();

			return OPT_RETURN;
		}
		else if((ch == 'c') || (ch == 'C') )
		{
			PUTCH(ch);

			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();

			return OPT_CANCEL;
		}
		else if((ch > ('0' + nMaxSelect)) || (ch < '0'))
		{
			//边界测试
			printf("\n..........>");
			continue;
		}
		else
		{
			PUTCH(ch);

			nSel = ch - '0';
			while((ch != '\n') && (ch != '\r'))
				ch=GETCH();

			if(nSel == 0)
			{
				return nDefaultSelect;
			}
			else
			{
				return nSel;
			}
		}
	}

	return nDefaultSelect;
}


int GetString(char *str, int maxSize)
{
	/*
#define OPT_EXIT        -1
#define OPT_RETURN        -2
#define OPT_PREVIOUS    -3
#define OPT_NEXT		-4
	*/
	int ch;
	int i = 0;

	*str = '\0';

	while(1)
	{
		ch = GETCH();

		if((ch == 'n') || (ch == 'N') || (ch == 13) || (ch == 10))
		{
			while((ch != 13) && (ch != 10))
				ch=GETCH();

			return OPT_NEXT;
		}
		else if((ch == 'e') || (ch == 'E') || (ch == 'q') || (ch == 'Q'))
		{
			/*[退出[E]]*/
			while((ch != 13) && (ch != 10))
				ch=GETCH();

			return OPT_EXIT;
		}
		else if((ch == 'P') || (ch == 'p'))
		{
			while((ch != 13) && (ch != 10))
				ch=GETCH();

			return OPT_PREVIOUS;
		}
		else if((ch == 'r') || (ch == 'R') || (ch == 'B') || (ch == 'b'))
		{
			while((ch != 13) && (ch != 10))
				ch=GETCH();

			return OPT_RETURN;
		}
		else if((ch == 'c') || (ch == 'C') )
		{
			while((ch != 13) && (ch != 10))
				ch=GETCH();

			return OPT_CANCEL;
		}
		else if (ch == '\b')
		{
			continue;
		}
		else
		{
			break;
		}
	}

	PUTCH(ch);
	str[i++] = ch;
	str[i] = '\0';

	while(1)
    {
		ch = GETCH();

		if((ch == '\n') || (ch == '\r'))
		{
            break;
		}
        else if(ch == '\b')
        {
			if (i)
			{
				printf("\b \b");
				str[--i] = 0;
			}
        }
        else
        {
            PUTCH(ch);
            str[i++] = ch;
            str[i] = 0;
        }
		//if (i>=maxSize)
		//	break;
    }

	return i;
}

int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i,j;

	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;

	if(itemName != NULL)
		printf("%s[%d]:\n",itemName,dataLength);

	for(i=0;i<(int)(dataLength/rowCount);i++)
	{
		printf("%08x  ",i*rowCount);
		for(j=0;j<(int)rowCount;j++)
		{
			printf("%02x ",*(sourceData+i*rowCount+j));
		}
		printf("\n");
	}
	if (!(dataLength%rowCount))
		return 0;

	printf("%08x  ",(dataLength/rowCount)*rowCount);
	for(j=0;j<(int)(dataLength%rowCount);j++)
	{
		printf("%02x ",*(sourceData+(dataLength/rowCount)*rowCount+j));
	}
	printf("\n");
	return 0;
}
