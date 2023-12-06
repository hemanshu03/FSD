import random

def shuffle(phrase, seed):
    size_phrase = len(phrase)
    random.seed(seed)
    rdm_array = list(range(size_phrase))
    random.shuffle(rdm_array)

    for j in range(size_phrase - 1, 0, -1):
        rdm_nb = rdm_array.pop()
        phrase[j], phrase[rdm_nb] = phrase[rdm_nb], phrase[j]

def unshuffle(phrase, seed):
    size_phrase = len(phrase)
    random.seed(seed)
    rdm_array = list(range(size_phrase))
    random.shuffle(rdm_array)

    for j in range(size_phrase - 1, -1, -1):
        rdm_nb = rdm_array.pop()
        phrase[j], phrase[rdm_nb] = phrase[rdm_nb], phrase[j]

# Example usage:
seed = 42  # You can change the seed value
phrase = list("Hello, World! randomly whatever it is fff")  # Convert the string to a list of characters
print("Original: ", ''.join(phrase))

shuffle(phrase, seed)
print("Shuffled: ", ''.join(phrase))

unshuffle(phrase, seed)
print("Unshuffled: ", ''.join(phrase))
