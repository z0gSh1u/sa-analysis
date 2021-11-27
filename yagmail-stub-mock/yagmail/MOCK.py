import random

def randomInRangeGauss(l, r, mu, sigma):
    while True:
        sample = random.gauss(mu, sigma)
        if sample >= l and sample < r:
            return sample

