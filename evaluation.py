import math
def sundaram3(max_n):
	numbers = range(3, max_n+1, 2)
	half = (max_n)//2
	initial = 4

	for step in xrange(3, max_n+1, 2):
		for i in xrange(initial, half, step):
			numbers[i-1] = 0
		initial += 2*(step+1)

		if initial > half:
			return [2] + filter(None, numbers)
			
def prob(percent,mulfix,nSieveSize,n):
	primes = sundaram3(nSieveSize)
	k=len(primes)
	p = primes[int(k*percent)]
	a=255*math.log(2)+math.log(1.5)+math.log(mulfix)+math.log(nSieveSize*n)
	b=math.log(p)
	return 1.78*b/a

def sieveEff(percent,prime,nSieveSize,nCh):
	primes = sundaram3(nSieveSize)
	k=len(primes)
	k = int(k*percent)
	e=1.;
	for i in range(0,k):
		if primes[i]>prime:
			e = e*(primes[i]-nCh)/primes[i]
	return e*nSieveSize