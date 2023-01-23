"""
    @Author: Murat Güç
    @Date:   November 28, 2022
"""


import helper
import pandas as pd
import re
import numpy as np 
from collections import Counter
import math


cipher_text = """Fwg atax: P’tx oh li hvabawl jwgvmjs, nw fw tfiapqz lziym,
rqgv uuwfpxj wpbk jxlnlz fptf noqe wgw.
Qoifmowl P bdg mg xv qe ntlyk ba bnjh vcf ekghn
izl fq blidb eayz jgzbwx sqwm lgglbtqgy xlip.
Pho fvvs ktf C smf ur ecul ywndxlz uv mzcz xxivw?
Qomdmowl P bgzg, oblzqdxj C swas,
B kyl btm udujs dcbfm vn yg eazl, pqzx,
oblzq Q’ow mwmzb lg ghvk gxslz, emamwx apqu, wwmazagxv nomy bhlustk.”
Ghm qvv’f nbfx h vqe vgoubdg, pgh’a nuvw shvbtmk kbvzq.
Baam jqfg pafs ixetqm wcdanw svc.
Kwn’df dixs mzy ziym llllmfa, zjid wxl
bf nom eifw hlqspuglowall, loyv sztq cu btmlw mhuq phmmla.
Kwn’df htiirk yul gx bf noqe kbls. Kwz’b agjl naz mzcuoe mekydpqzx:
lblzq’a gg moqb nhj svc, fpxjy’z va zhsx.
Uwi basn fwg’dx ouzbql rgoy tunx zyym, uv mzcz ayied wvzzmk,
qib’dq lxknywkmw an ldqzroblzq qg lbl eazev."""


### FIND KEY LENGTH ###

#getting rid of spaces,commas,etc. and numbers
pure_cipher = ''.join(word for word in re.findall(r"[\w']+", cipher_text) if not word.isdigit()).lower()
#print(pure_cipher)

#works for 3,4,5
particle_size = 4
max_key_size = 40

#particles extracted
particles = [pure_cipher[index:index+particle_size] for index in range(len(pure_cipher)-(particle_size-1))]

#dataframe created for each particle and its corresponding next occurence in pure text initialized as None
df = pd.DataFrame({"particles":particles,"next_occ": None})

#next occurence column is calculated
temp_cipher = pure_cipher
for ind in range(len(particles)):
    unit = df["particles"][ind]
    temp_cipher = temp_cipher[1:]
    try:
        df.at[ind,'next_occ']=temp_cipher.index(unit)+1
    except:
        continue

#getting rid of none values in next_occ column
df=df.dropna()

#possibility of key length initialized
for i in range(max_key_size-1):
    df[i+2]=0  

#divisors of next_ecc values distributed to key lengths
for j in df.index:
    for k in range(max_key_size-1):
        if df.at[j,'next_occ']%(k+2)==0 and df.at[j,'next_occ']!=0:
            df.at[j,k+2]=1

#finding the most frequent key length in the table
dfSum=df.drop(['particles', 'next_occ'], axis=1).T.sum(axis = 1)
key_length = dfSum[dfSum == dfSum.max()].index[0]

print(f"key length: {key_length}")

### ### FIND KEY ### ###

#    key, length of 7
#    _ _ _ _ _ _ _
# %  0 1 2 3 4 5 6

#this function iterates over 7(key length) mod like 0(0,7,14...) 1(1,8,15...)
#then returns letter frequency dictionary acc to _ind
def letter_frequency_at_by_mod(_string,_ind,_mod):
    # copying the struct, values will be modified
    acc_str = ""
    for i in range(int(len(_string)/_mod)):
        acc_str += _string[_mod*i+_ind]
    return {k: round((v / total * 100),2) for total in (sum(Counter(acc_str).values(), 0.0),) for k, v in Counter(acc_str).items()}

#this method pops first item in the dict and add it to the last.
def shift_one_dict(_dict):
    key = list(_dict.items())[0][0]
    val = _dict.pop(list(_dict.items())[0][0])
    _dict.update({key:val})
    return _dict

#if there are some missings in the return of letter_frequency_at_by_mod method
#it adds the missing letter and its corresponding value becomes 0
def fix_missings(_dict):
    for ind, letter in helper.inv_lowercase.items():
        if _dict.get(letter) is None:
            _dict.update({letter:0})
    return _dict

#while comparing two frequency dict, this method calculates error by (difference)^2
#then returns sum of squares
def error_fuction_of_freqs(_f1,_f2):
    f1_vals = np.array(list(_f1.values()))
    f2_vals = np.array(list(_f2.values()))
    return  np.sum((f1_vals-f2_vals)**2)

#this method is used for sorting arrays in terms of letters to compute easily
def sort_dict(_dict):
    return dict(sorted(_dict.items()))

#this method is used for finding shift(key character unit), by comparing two freq dict
#thanks to the error calculation, it finds perfect frequency distribution corresponding
def char_of_key(_fgs1,_fgs2):
    error=math.inf
    last_s = 0
    for shift in range(25):
        err = error_fuction_of_freqs(_fgs1,_fgs2)
        if err<error:
            error=err
            last_s=shift
        shift_one_dict(_fgs2)    
    return chr(last_s+ord('a'))

#this function generates key 
def key():
    key_str = ""
    lt_freq_given_sorted = sort_dict(helper.letterFrequency)
    for ind in range(key_length):
        lt_freq_calc = letter_frequency_at_by_mod(pure_cipher,ind,key_length)
        lt_freq_calc_sorted = sort_dict(fix_missings(lt_freq_calc))
        key_str += char_of_key(lt_freq_given_sorted,lt_freq_calc_sorted)
    return key_str
    
key = key()
print(f"key: {key}")
    

### ### DECRYPTION ### ###

key_shifts = [ord(char) - ord('a') for char in key]

plain_text = ""
counter = 0
for char in cipher_text:
    if char.isalpha():
        if ord(char)-key_shifts[counter%7]>=(ord('a') if char.islower() else ord('A')):
            plain_text+=chr(ord(char)-key_shifts[counter%7])
            counter+=1
        else:
            plain_text+=chr(ord(char)-key_shifts[counter%7]+26)
            counter+=1
    else:
        plain_text+=char


print(plain_text)

#it opens a file then, writes key and plaintext on it.
fs = open("q2_out.txt", "wb")

fs.write(f"{key}\n\n{plain_text}".encode())        

fs.close()



