# threshold-signature-demo

Python3 TS demo, no any pip requirements.

# Structure

- [crypto.py](/crypto.py), hash functions, base58check encoder and decoder
- [meta.py](/meta.py), operations of bitcoin objects, such as `int_to_varint`, `serialize_public_key`, `public_key_to_address`, etc.
- [modular_inverse.py](/modular_inverse.py), calculate the modular multiplicative inverse of integer `a` under modulo `n`
- [ec_point_operation.py](/ec_point_operation.py), points add and scalar multiply operations on Secp256k1 curve
- [sign.py](/sign.py), ECDSA implementation, sign and verify ECDSA signature (r, s)
- [sign_transaction.py](/sign_transaction.py), functions to sign a bitcoin transaction
- [sign_message.py](/sign_message.py), use bitcoin private key to sign arbitrary message
- [polynomial.py](/polynomial.py), implementation of polynomial `y = a0 * x^0 + a1 * x^1 + ... + at * x^t` on finite field Secp256k1.n
- [threshold_signature.py](/threshold_signature.py), TS operations, `jvrss`, `addss`, `pross` and `invss`
- [ts_demo.py](/ts_demo.py), a demo with detailed process logs

# Sign arbitrary message

Run [threshold_signature.py](/threshold_signature.py)

```
Threshold Signature Scheme Sign Test
Private key shares:
[58704453192427097668905478943708558237974193247046745563496959203322823742893, 23188773853202535877504805516765027095629763648304818244515056158537811924307, 103465183751294169509675117098509403806122898328637795308138316255270961600058]
------------------
12GxHurZSe8AiqYRFgVHSMsbxyK3KrBXz8 H9BnqUffdGO7O7TbRAOOE4JgOkh52vAv0yHC1uvSHSmXGDw2uRM35HzgnTgzYWIHFm1LfMo3Qw3QNPs/BzE6i8s=
------------------
True
```

Check outputs with online [Bitcoin Signature Tool](https://reinproject.org/bitcoin-signature-tool/), great!

![](https://aaron67-public.oss-cn-beijing.aliyuncs.com/20201019230006.png)

# Demo

If specify `debug = True`, the polynomial will only random coefficients between `1` and `10`, else between `1` and `Secp256k1.n`.

Run [ts_demo.py](/ts_demo.py).

```
---------------------- demo ----------------------
group size = 3
key threshold = 2
signature threshold = 3
polynomial order = 1

------------ jvrss ------------
Player 1 <Polynomial order=1, coefficients=[5, 2]>
Player 2 <Polynomial order=1, coefficients=[6, 2]>
Player 3 <Polynomial order=1, coefficients=[3, 7]>
f1(1) = 7	f1(2) = 9	f1(3) = 11	
f2(1) = 8	f2(2) = 10	f2(3) = 12	
f3(1) = 10	f3(2) = 17	f3(3) = 24	
secret = 14
mod_inv_secret = 74437771652560411343724204648442226476824148465119581388817604876690246674931
public key = (33301309993451753050311554695703528430361259803437469669590207169100761277412, 91711666877231500617203373035680263572492971120307578300405368749466283229019)
shares = [25, 36, 47]
-------------------------------
shares = [25, 36, 47]
public_key = (33301309993451753050311554695703528430361259803437469669590207169100761277412, 91711666877231500617203373035680263572492971120307578300405368749466283229019)
restored key = 13

------------ jvrss ------------
Player 1 <Polynomial order=1, coefficients=[7, 3]>
Player 2 <Polynomial order=1, coefficients=[8, 7]>
Player 3 <Polynomial order=1, coefficients=[5, 4]>
f1(1) = 10	f1(2) = 13	f1(3) = 16	
f2(1) = 15	f2(2) = 22	f2(3) = 29	
f3(1) = 9	f3(2) = 13	f3(3) = 17	
secret = 20
mod_inv_secret = 40527231233060668398249844753040767748493147497676216533911807099531356523018
public key = (34773495056115281091786765947597603724784643419904767525769502836017890139287, 8470533044743364938367028725608288731153024648869546164814808839694950063162)
shares = [34, 48, 62]
-------------------------------
another shares = [34, 48, 62] 

------------ addss ------------
[25, 36, 47]
[34, 48, 62]
shares addition = [59, 84, 109]
points picked = [(3, 109), (1, 59)]
secrets addition = 33
-------------------------------
shares addition = 33 

------------ pross ------------
[25, 36, 47]
[34, 48, 62]
shares product = [850, 1728, 2914]
points picked = [(1, 850), (2, 1728), (3, 2914)]
secrets product = 280
-------------------------------
shares product = 280 

------------ invss ------------
[25, 36, 47]
------------ jvrss ------------
Player 1 <Polynomial order=1, coefficients=[9, 4]>
Player 2 <Polynomial order=1, coefficients=[4, 4]>
Player 3 <Polynomial order=1, coefficients=[3, 1]>
f1(1) = 13	f1(2) = 17	f1(3) = 21	
f2(1) = 8	f2(2) = 12	f2(3) = 16	
f3(1) = 4	f3(2) = 5	f3(3) = 6	
secret = 16
mod_inv_secret = 108555083659983933209597798445644913612035216511632722858692340445173276400941
public key = (104059883622109321374094289636044428849728529177856482232626205340719788190730, 112122903140080327253741791678230372394936108416576609264408917599318947489825)
shares = [25, 34, 43]
-------------------------------
------------ pross ------------
[25, 36, 47]
[25, 34, 43]
shares product = [625, 1224, 2021]
points picked = [(1, 625), (3, 2021), (2, 1224)]
secrets product = 224
-------------------------------
u = 224
mod_inv_u = 98733433233604434490634188110086564285232030255818333647667795357276646631332
inverse shares = [36701956856470758370864017569718042221211906534885349156986457960034774402223, 114758231297697300821574815499681765818437228883726021307760474184897463623852, 77022416501607647848714628420957581562824986953491789075929327268241991351144]
points picked = [(3, 77022416501607647848714628420957581562824986953491789075929327268241991351144), (1, 36701956856470758370864017569718042221211906534885349156986457960034774402223), (2, 114758231297697300821574815499681765818437228883726021307760474184897463623852)]
inverse secret = 74437771652560411343724204648442226476824148465119581388817604876690246674931
-------------------------------
inverse shares = [36701956856470758370864017569718042221211906534885349156986457960034774402223, 114758231297697300821574815499681765818437228883726021307760474184897463623852, 77022416501607647848714628420957581562824986953491789075929327268241991351144] 

--------------------------------------------------
```

# Reference

- [Threshold Signature Paper](https://nakasendoproject.org/Threshold-Signatures-whitepaper-nchain.pdf) of nChain
- [AustEcon/bitsv](https://github.com/AustEcon/bitsv)
