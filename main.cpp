#include <NTL/ZZ.h>
#include <NTL/vec_ZZ.h>
#include <NTL/mat_ZZ.h>
#include <time.h>
#include <cmath>

NTL_CLIENT

ZZ assistant_algorithm(ZZ a, ZZ q);//the round-off of a/q
ZZ my_mod(ZZ a, ZZ q);//the new mod
vec_ZZ SecretKeygen(ZZ q, long n);//SecretKeygen(1")
vec_ZZ gets_(vec_ZZ s, long n);//get s'
mat_ZZ PublicKeygen(vec_ZZ s_, ZZ q, long n);//PublicKeygen(s)
vec_ZZ Enc(mat_ZZ A, ZZ q, long n, int msg);//Enc(pk, m)
ZZ Dec(vec_ZZ c, vec_ZZ s, ZZ q);//Dec(sk, c)

int main(void)
{
    long n;//the length n
    int msg;//the original message
    ZZ q, m;//the mod q and the decoded message m
    vec_ZZ s, c;//the sk -> s and the ciphertext ->c
    mat_ZZ A;//the pk -> A
    cout << "Please enter the number q : ";
    cin >> q;//get q
    cout << "\nPlease enter the number n : ";
    cin >> n;//get n
    s = SecretKeygen(q, n);//SecretKeygen(1")
    A = PublicKeygen(gets_(s, n), q, n);//PublicKeygen(s)
    cout << "\nPlease enter the message : ";
    cin >> msg;//get the original message
    c = Enc(A, q, n, msg);//Enc(pk, m)
    cout << "\nc = " << c;
    m = Dec(c, s, q);//Dec(sk, c)
    cout << "\n\nThe decoded message is : "<< m;
    return 0;
}

ZZ my_mod(ZZ a, ZZ q)//the new mod
{
    return a - q * assistant_algorithm(a, q);
}

ZZ assistant_algorithm(ZZ a, ZZ q)//the round-off of a/q
{
	ZZ tmp;
	tmp = a * 10 / q;
	if (tmp % 10 >= 5)
	{
		return a / q + 1;
	}
	else
	{
		return a / q;
	}
}

vec_ZZ SecretKeygen(ZZ q, long n)//SecretKeygen(1")
{
    vec_ZZ s;
    int i;
    srand(time(NULL));//seed
    s.SetLength(n+1);//set the length of the vector s
    s(1) = 1;
    for (i = 1; i <= n; i++)//assign to the vector s
    {
        s(i + 1) = my_mod(to_ZZ(rand() + q), q);
    }
    return s;//return s -> sk
}

vec_ZZ gets_(vec_ZZ s, long n)//get s'
{
    vec_ZZ s_;
    int i;
    s_.SetLength(n);//set the length of the vector s'
    for (i = 1; i <= n; i++)
    {
        s_(i) = s(i + 1);//assign to vector s'
    }
    return s_;
}

mat_ZZ PublicKeygen(vec_ZZ s_, ZZ q, long n)//PublicKeygen(s)
{
    long N = 2 * n * ceil(log(q)/log(2));
    int i, j;
    mat_ZZ A_, A;
    vec_ZZ e, b;
    A_.SetDims(N, n);//set the rank of the matrix A'
    A.SetDims(N, n + 1);//set the rank of the matrix A
    e.SetLength(N);//set the length of the vector e
    for (i = 1; i <= N; i++)
    {
        for (j = 1; j <= n; j++)
        {
            A_(i)(j) = my_mod(to_ZZ(rand() + q), q);//assign to the matrix A'
        }
        e(i) = rand() % 3 - 1;//assign to the vector e
    }
    b = A_ * s_ + e;
    for (i = 1; i <= N; i++)//assign to the matrix A
    {
        A(i)(1) = b(i);
        for (j = 2; j <= n + 1; j++)
        {
            A(i)(j) = my_mod(A_(i)(j - 1) * -1, q);
        }
    }
    return A;//return A -> pk
}

vec_ZZ Enc(mat_ZZ A, ZZ q, long n, int msg)//Enc(pk, m)
{
    long N = 2 * n * ceil(log(q)/log(2));
    int i;
    vec_ZZ m, r, c, tmp1, tmp3;
    mat_ZZ tmp2;
    m.SetLength(n + 1);//set the length of the vector m
    r.SetLength(N);//set the length of the vector r
    m(1) = msg;
    for (i = 2; i <= n + 1; i++)//assign to the vector m
    {
        m(i) = 0;
    }
    for (i = 1; i <= N; i++)//assign to the vector r
    {
        r(i) = i % 2;
    }
    //c = my_mod(q / 2 * m + transpose(A) * r, q);
    tmp1 = (q / 2) * m;
    tmp2 = transpose(A);
    tmp3 = tmp2 * r;
    c = tmp1 + tmp3;
    for (i = 1; i <= n + 1; i++)
    {
        c(i) = my_mod(c(i), q);
    }
    return c;//return c -> ciphertext
}

ZZ Dec(vec_ZZ c, vec_ZZ s, ZZ q)//Dec(sk, c)
{
    ZZ tmp = my_mod(c * s, q);
    tmp = assistant_algorithm(tmp * 2, q);
    tmp = tmp % 2;
    return tmp;//return tmp -> the decoded message
}
