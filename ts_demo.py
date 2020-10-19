from threshold_signature import ThresholdSignature
import random

ts = ThresholdSignature(group_size=3, threshold=2)

debug = True
print('---------------------- demo ----------------------')

# group info
print(f'group size = {ts.group_size}')
print(f'key threshold = {ts.key_threshold}')
print(f'signature threshold = {ts.signature_threshold}')
print(f'polynomial order = {ts.polynomial_order}')
print()

# Generate shares of secret a
a_shares, a_pubkey = ts.jvrss(debug)
print('shares =', a_shares)
print('public_key =', a_pubkey)
print('restored key =', ts.restore_key(random.sample(ThresholdSignature.shares_to_points(a_shares), ts.key_threshold)))
print()

# Generate shares of another secret b
b_shares, _ = ts.jvrss(debug)
print('another shares =', b_shares, '\n')

# Calculate addition of secret a and b, with a shares and b shares, without knowing a and b
print('shares addition =', ts.addss(a_shares, b_shares, debug), '\n')

# Calculate product of secret a and b, with a shares and b shares, without knowing a and b
print('shares product =', ts.pross(a_shares, b_shares, debug), '\n')

# Calculate shares of modular multiplicative inverse of secret a, with shares of a, without knowing a
print('inverse shares =', ts.invss(a_shares, debug), '\n')

print('--------------------------------------------------')
