from sender import SMTP
import time
from tqdm import tqdm

LOGIN_TIME = 3 # secs
SEND_COUNT = 500

# test for `performance` part
def test1():
    tic = time.time()
    smtp = SMTP(user='MOCK')
    toc = time.time() + LOGIN_TIME
    print("[PERF] Initial overhead: {:.3f} secs.".format(toc - tic))

    tic = time.time()
    for i in tqdm(range(SEND_COUNT)):
        smtp.send()
    toc = time.time()
    
    print("[PERF] Total time elapsed: {:.3f} secs.".format(toc - tic))
    print("[PERF] Total network RTT: {:.3f} secs.".format(smtp.slpTimesTot))
    print("[PERF] Failure count: {}.".format(smtp.failureCount))
    print("[PERF] Cached errors: ")
    print(smtp.errors)

if __name__ == '__main__':
    test1()
