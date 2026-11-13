#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#define c_isdigit(c) ((c)>=0x30 && (c)<=0x39)
#define c_isalpha(c) (((c)>=0x41 && (c)<=0x5a)||((c)>=0x61&&(c)<=0x7a))
static int
order(int c)
{
	if (c_isdigit(c))
		return 0;
	else if (c_isalpha(c))
		return c;
	else if (c == '~')
		return -1;
	else if (c)
		return c + 256;

	return 0;
}

static int
verrevcmp(const char *a, const char *b)
{
	if (a == NULL)
		a = "";
	if (b == NULL)
		b = "";

	while (*a || *b) {
		int first_diff = 0;

		while ((*a && !c_isdigit(*a)) || (*b && !c_isdigit(*b))) {
			int ac = order(*a);
			int bc = order(*b);

			if (ac != bc)
				return ac - bc;

			a++;
			b++;
		}
		while (*a == '0')
			a++;
		while (*b == '0')
			b++;
		while (c_isdigit(*a) && c_isdigit(*b)) {
			if (!first_diff)
				first_diff = *a - *b;
			a++;
			b++;
		}

		if (c_isdigit(*a))
			return 1;
		if (c_isdigit(*b))
			return -1;
		if (first_diff)
			return first_diff;
	}

	return 0;
}
struct v { long e; char *u; const char *r; };
static void pv(struct v *o, char *s){ char *c=strchr(s,':'); o->e=0; if(c){char *end; o->e=strtol(s,&end,10); if(end!=c||end==s||!c[1]) o->e=-99; s=c+1;} char *h=strrchr(s,'-'); if(h){*h++=0; o->r=h;} else o->r=""; o->u=s; }
int main(){ char a[512],b[512]; while(scanf("%511s %511s",a,b)==2){ struct v x,y; pv(&x,a); pv(&y,b); int rc; if(x.e==-99||y.e==-99){printf("X\n");continue;} if(x.e!=y.e) rc = x.e>y.e?1:-1; else { rc=verrevcmp(x.u,y.u); if(!rc) rc=verrevcmp(x.r,y.r);} printf("%d\n", rc>0?1:rc<0?-1:0);} return 0; }
