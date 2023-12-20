# Bitcoin task
The goal of this lab is to get familiar with blockchain (and bitcoin as the famous example of this technology) and brute force attacks.

There exists a fairly popular site https://www.bitaddress.org which allows you to generate new bitcoin addresses in your browser. For the purposes of this homework we have modified the site and introduced a vulnerabiliy and upload the vulnerable code here.

The task is to find a private key for existing bitcoin wallet with real money on it. Based on your personal preferences you can follow either of following stories.

## Story 1 - Good guy (at least at beggining?)
There are multiple incidents of bitcoin stealing - as this is not actually unpossible (today), guys just had to share their private keys, right? Well, most of them used unofficial clone of bitaddress.org.html website to generate their keys. As the algorithm is written in java-script and included into html website, you can run the code localy. Many of them did so and still - someone rob their money! Get in touch with the code and find how it is possible. For which address(es) with real money did you find a private key? Will you aware a community? (Will you grap the money?)

## Story 2 - Evil guy
There is popular key generator [NOTE: modified for purpose of this exercise]. It is used by many guys to (securely) get their own unique keys. Well, securely. But, can you look into the code and find vulnerability? Can you somehow brute force generated keys and find some with money? Let's steal some money!

# The task
You will complete the homework by sending the correct private key to me via email along with **text description and code** of your solution.


# The solution
First, we spot the difference between the original and the alternated web page via downloading the html and preforming `diff`. The difference is on lines `5654-5657` in

    			this.priv = ECDSA.getBigRandom(n)
				.mod(BigInteger.valueOf(3000))
				.multiply(new BigInteger("424242424242424244242424244242424242424"))
				.add(new BigInteger("SoLongAndThanksForAllTheFish"));

Obviously, the key space is reduced to only 3000 possible private keys. We bruteforce all the possibilities using JavaScript script `gen_script.txt` (alternated to .txt as Gmail forbids sending .js files) run in web browser console. 
The generated pairs are stored in `key_database.txt`

We then use API of blockchain info webpage (https://www.blockchain.com/api/blockchain_api) to ask for number of transactions for each generated address (public key). 
The API query results are stored in results.json
The pair is:

generated by value : `2562`
Private key: `KwDiBf89QgGbjEhKnhXJuY4GUMKjkbiQLBXrUaWStqmWnp3XBMte`
Public key: `1E2mSN7MXVuS4ecafhTLtaokf5RixcYUEU`