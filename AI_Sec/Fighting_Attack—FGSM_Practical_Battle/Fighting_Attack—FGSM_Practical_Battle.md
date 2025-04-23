# Fight against Attack—FGSM actual combat

Author: H3rmesk1t

Data: 2022.04.26

# paper
## Paper information
[Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572).

## Introduction to the paper
Early speculations on the causes of adversarial samples focused on the nonlinearity and overfitting of neural networks, but this paper proved that the linear nature of neural networks is the main reason for neural networks to have adversarial samples. At the same time, this paper proposes a method that can generate adversarial samples more easily and faster.

## Main content of the paper
 - The adversarial samples are negatively caused by nonlinearity and overfitting, and it is believed that the adversarial samples are caused by the linearity of neural networks in high-dimensional space, and a large number of experiments are proposed to illustrate. Adversarial samples can be interpreted as an attribute of point multiplication in high-dimensional space, and they are the result of the model being too linear.
 - The linearity of the model makes it easier to train, while its nonlinearity makes it easy to resist attacks against perturbations, that is, models that are easily optimized are also easily perturbed.
 - A particularly fast method for generating adversarial samples `FGSM` is proposed:

<div align=center><img src="./images/2.png"></div>

 - The essence of `FGSM` is that the input image adds some perturbation in the weight direction of the model (the direction is the same, point multiplies the maximum). This allows the image to change significantly under smaller perturbations, thereby obtaining confrontation samples.
 - Generalization of adversarial examples between different models can be interpreted as that adversarial perturbations are highly consistent with the weight vector of the model, and that different models learn similar functions when training to perform the same task.
 - A regularization method based on `FGSM` was proposed. Adversarial training can be used for regularization, and the effect is even better than `dropout`:

<div align=center><img src="./images/1.png"></div>

 - Compared with model fusion, a single model has better adversarial defense capabilities, and the integration strategy cannot resist adversarial samples.
 - Linear models lack the ability to resist adversarial perturbations, and only structures with hidden layers (when the universal approximation theorem applies) should be trained to resist adversarial perturbations.
 - The `RBF` network can resist adversarial samples.
 - Distribution characteristics of adversarial samples, that is, adversarial samples often exist near the model's decision boundary. In the online search range, the normal classification area of ​​the model and the area attacked by adversarial samples only account for a small part of the distribution range, and the remaining part is a rubbish class.
 - Garbage category samples are ubiquitous and easy to generate, shallow linear models cannot resist garbage category samples, and the `RBF` network can resist garbage category samples.

# FGSM
## Principle
`fast gradient sign method` is an algorithm that generates adversarial samples based on gradients. It belongs to targetless attacks in adversarial attacks, that is, the adversarial samples are not required to predict the specified category through `model`, as long as they are different from the original sample prediction. It aims to attack neural networks by using model learning methods and gradients. The attack adjusts the input data to maximize losses based on the same backpropagation gradient, rather than minimize losses by adjusting the weight based on backpropagation gradients. In short, an attack is to utilize the gradient of the loss function and then adjust the input data to maximize losses.

For example, in the picture below, a certain disturbance (noise point) is added to the giant panda photo, and after inputting `model`, it is judged to be a gibbon.

<div align=center><img src="./images/3.png"></div>

## Formula
The `FGSM` formula is shown in the figure below:

<div align=center><img src="./images/2.png"></div>

In the formula, `x` is the original sample; `θ` is the weight parameter of the model, that is, `w`; `y` is the real category of `x`. Enter the original sample, weight parameters and real category, and find the loss value of the neural network through the `J` loss function. `∇x` means to find partial derivative of `x`, that is, the loss function `J` find partial derivative of `x` sample. `sign` is a symbolic function, that is, `sign(-1)`, `sign(-99.9)`, etc. are all equal to `-1`; `sign(1)`, `sign(99.9)`, etc. are all equal to `1`. The value of `epsilon` is usually set by humans and can be regarded as the learning rate. Once the perturbation value exceeds the threshold, the adversarial sample will be recognized by the human eye.

<div align=center><img src="./images/4.png"></div>

## algorithm
### Build a model

```python
# Library file introduction
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import numpy as np
import matplotlib.pyplot as plt
from __future__ import print_function
from torchvision import datasets, transforms

# Set up multiple epsilons to facilitate subsequent visualization of their impact
epsilons = [0, .05, .1, .15, .2, .25, .3, .35, .4, .45, .5]

# Load the pretrained model
# Pre-trained model download address: https://drive.google.com/drive/folders/1fn83DF14tWmit0RTKWRhPq5uVXt73e0h
pretrained_model = 'data/lenet_mnist_model.pth'

# Whether to use cuda
use_cuda = False

# Build an attacked model
# Define the LeNet model
class LeNet(nn.Module):
    def __init__(self):
        super(LeNet, self).__init__()
        self.conv1 = nn.Conv2d(1, 10, kernel_size=5)
        self.conv2 = nn.Conv2d(10, 20, kernel_size=5)
        self.conv2_drop = nn.Dropout2d()
        self.fc1 = nn.Linear(320, 50)
        self.fc2 = nn.Linear(50, 10)
        
    def forward(self, x):
        x = F.relu(F.max_pool2d(self.conv1(x), 2))
        x = F.relu(F.max_pool2d(self.conv2_drop(self.conv2(x)), 2))
        x = x.view(-1, 320)
        x = F.relu(self.fc1(x))
        x = F.dropout(x, training=self.training)
        x = self.fc2(x)
        return F.log_softmax(x, dim=1)

# Download and load the dataset
loader = torch.utils.data.DataLoader(
    datasets.MNIST('data/', train=False, download=True, transform=transforms.Compose([
        transforms.ToTensor(),
    ])),
    batch_size=1,
    shuffle=True
)

# Configure GPU
cuda_available = torch.cuda.is_available()
device = torch.device('cude' if (use_cuda and cuda_available) else 'cpu')
print('CUDA is available: ', cuda_available)

# Initialize the network model
model = LeNet().to(device)
# Load the pretrained model
model.load_state_dict(torch.load(pretrained_model, map_location='cpu'))
# Set to verification mode
model.eval()
```

<div align=center><img src="./images/5.png"></div>

### FGSM Attack Module

```python
# FGSM Attack Module
def fgsm_attack_module(image, epsilon, data_grad):
    # Use the sign symbol function to symbolize the gradient in which the partial derivative is found on x
    sign_data_grad = data_grad.sign()
    # Generate adversarial samples through epsilon
    adversarial_image = image + epsilon * sign_data_grad
    # Do a tailoring job, change the value greater than 1 in torch.clamp to 1, and the value less than 0 is equal to 0 to prevent image from crossing bounds
    adversarial_image = torch.clamp(adversarial_image, 0, 1)
    # Return to the adversarial sample
    return adversarial_image
```

### Test module

```p
ython
def test( model, device, test_loader, epsilon):

    # Accuracy Counter
    correct = 0
    # Confrontation Sample
    adv_examples = []

    # Loop through all examples in the test set
    for data, target in test_loader:

        # Send data and tags to the device
        data, target = data.to(device), target.to(device)

        # Set the tensor's requirements_grad property, which is critical for attacks
        data.requires_grad = True

        # Pass data forward through the model
        output = model(data)
        init_pred = output.max(1, keepdim=True)[1] # get the index of the max log-probability

        # If the initial prediction is wrong, do not interrupt the attack and continue
        if init_pred.item() != target.item():
            Continue continue

        # Calculate the loss
        loss = F.nll_loss(output, target)

        # Zero all existing gradients
        model.zero_grad()

        # Calculate the gradient of the backward pass model
        loss.backward()

        # Collect datagrad
        data_grad = data.grad.data

        # Wake up FGSM to attack
        perturbed_data = fgsm_attack_module(data, epsilon, data_grad)

        # Reclassify disturbed images
        output = model(perturbed_data)

        # Check whether it is successful
        final_pred = output.max(1, keepdim=True)[1] # get the index of the max log-probability
        if final_pred.item() == target.item():
            correct += 1
            # Save 0 special examples of epsilon example
            if (epsilon == 0) and (len(adv_examples) < 5):
                adv_ex = perturbed_data.squeeze().detach().cpu().numpy()
                adv_examples.append( (init_pred.item(), final_pred.item(), adv_ex) )
        else:
            # Save some examples for visualization later
            if len(adv_examples) < 5:
                adv_ex = perturbed_data.squeeze().detach().cpu().numpy()
                adv_examples.append( (init_pred.item(), final_pred.item(), adv_ex) )

    # Calculate the final accuracy of this epsilon
    final_acc = correct / float(len(test_loader))
    print("Epsilon: {}\tTest Accuracy = {} / {} = {}".format(epsilon, correct, len(test_loader), final_acc))

    # Returns accuracy and adversarial examples
    return final_acc, adv_examples
```

### Visual result comparison module
```python
# Start attack
accuracy = []
examples = []

# Run test for each epsilon
for eps in epsilons:
    acc, ex = test(model, device, loader, eps)
    accuracies.append(acc)
    examples.append(ex)

plt.figure(figsize=(5,5))
plt.plot(epsilons, accuracy, "*-")
plt.yticks(np.arange(0, 1.1, step=0.1))
plt.xticks(np.arange(0, .35, step=0.05))
plt.title("Accuracy vs Epsilon")
plt.xlabel("Epsilon")
plt.ylabel("Accuracy")
plt.show()
```

<div align=center><img src="./images/6.png"></div>

### Sample and Adversarial Sample Comparison Module

```python
# Plot several examples of adversarial samples at each epsilon
cnt = 0
plt.figure(figsize=(8,10))
for i in range(len(epsilons)):
    for j in range(len(examples[i])):
        cnt += 1
        plt.subplot(len(epsilons),len(examples[0]),cnt)
        plt.xticks([], [])
        plt.yticks([], [])
        if j == 0:
            plt.ylabel("Eps: {}".format(epsilons[i]), fontsize=14)
        orig,adv,ex = examples[i][j]
        plt.title("{} -> {}".format(orig, adv))
        plt.imshow(ex, cmap="gray")
plt.tight_layout()
plt.show()
```

<div align=center><img src="./images/7.png"></div>

# Practical combat
Let’s briefly understand how `FGSM` is used in application scenarios through several `CTF` questions.

## N1CTF2021 Collision
A code file and a model parameter are given in the attachment of the title. Let’s take a look at the code first:

```python
import base64

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F


class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.dropout1 = nn.Dropout(0.25)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x):
        x = self.conv1(x)
        x = F.relu(x)
        x = self.conv2(x)
        x = F.relu(x)
        x = F.max_pool2d(x, 2)
        x = self.dropout1(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        Return x


def load_model(path):
    model = Net()
    model.load_state_dict(torch.load(path, map_location="cpu"))
    return model.eval()


model = load_model("convNet.pt")


def hex_hash(hash_bits):
    x = hash_bits.detach().nu
mpy()
    res = [str(int(i > 0)) for i in x[0]]
    return hex(int(''.join(res), 2))


L0_THRES = 54.1
L2_THRES = 6.45
src = np.frombuffer(base64.b64decode(
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAA5eTkPgAAgD/l5GQ+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPiYj8AAIA/5eRkPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOno6D0AAIA/5eTkPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADl5OQ+AACAP62srD4AAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx8ZGPwAAgD/p6Og9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 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'),
                    dtype="float32")


def hash_buf(buf):
    global src
    arr = np.frombuffer(buf, dtype="float32")
    if arr.shape[0] != 28 * 28:
        raise BufferError("hacker")
    arr = np.clip(arr, 0, 1)
    diff = arr - src
    #print(np.linalg.norm(diff, 0), np.linalg.norm(diff, 2))
    if np.linalg.norm(diff, 0) > L0_THRES or np.linalg.norm(diff, 2) > L2_THRES:
        raise BufferError("attack failed")
    arr = torch.FloatTensor(arr).reshape(1, 1, 28, 28)
    # need=0x1046822029745355ca048937f624fb87
    # hash(src)=0x91460a702d62d166a9942cb7fc10d7a2
    return hex_hash(model(arr))
```

### analyze
First, a `CNN` model `Net` is given in the code, similar to the `LeNet` implemented above.

Next, the `load_model` function initializes the model and loads the existing `convNet.pt` model parameters.

In the `hex_hash` method, the numerical values ​​of the given `numpy` array are mapped to `0` and `1`. When the array element is less than or equal to `0`, the corresponding `hash` value is `0`, otherwise it is `1`, thereby generating the `hash` value.

Then, two norm constraints commonly found in image attacks are given, For details, you can take a look at the previous [Learning against Attacks from Papers - Summary] (https://github.com/H3rmesk1t/Learning_summary/blob/main/AISec/%E5%AF%B9%E6%8A%97%E6%94%BB%E5%87%BB/%E4%BB%8E%E8%AE%BA%E6%96%87%E5%AD%A6%E4%B9%A0%E5% AF%B9%E6%8A%97%E6%94%BB%E5%87%BB%E2%80%94%E7%BB%BC%E8%BF%B0/%E4%BB%8E%E8%AE%BA%E6%96%87%E5%AD%A6%E4%B9%A0%E5%AF%B9%E6%8A%97%E6%94%BB%E5%87%BB%E2%80%94%E7%BB%BC%E8%BF%B0.md), And the `Base64` value as the comparison picture. First restore the comparison picture. The restored picture is `4` in the `MNIST` dataset, which also echoes the number of units in the last output layer of the `Net` model is `10`:

```python
import cv2
import base64
import numpy as np

src = np.frombuffer(base64.b64decode('AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5eTkPgAAgD/l5GQ+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPiYj8AAIA/5eRkPgAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOno6D0AAIA/5eTkPgAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADl5OQ+AACAP62srD4AAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAx8ZGPwAAgD/p6Og9AAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6ejoPQAAgD/j4mI/AAAAAAAAAAAAAAAA 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'),dtype="float32")
src = src.reshape((28,28,1))
cv2.imshow("test_img", src)
cv2.waitKey()
```

<div align=center><img src="./images/8.png"></div>

Finally, let’s take a look at the `hash_buf` method. First, receive the bitstream decoded by the attack image `base64`, then convert it into a `float32` array, then judge the size of the attack image, and then force constraints the image pixel value to `[0,1]`. If the pixel value is less than `0`, it will become `0`, greater than `1`, and the others will remain unchanged.

Then, based on the difference between the attack image and the comparison image, we will find `l0` and `l2`. If the requirements are not met, it will fail. If the requirements are met, the sent image is sent to the network, and the eigenvalue array of the penultimate layer is taken out and the `numpy` is converted into `hash` value. If the calculated `hash` value is equal to `0x1046822029745355ca048937f624fb87`, the attack is successful.

### Solve the problem
According to the above analysis ideas, it is necessary to generate an attack picture with an attack size of `28 * 28` calculated according to the method in the code calculated according to the method in the code.

The corresponding EXP is as follows:

```python
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.autograd import Variable
from pwn import *
from PIL import Image
import hashlib
import string

class Net(nn.Module):
    def __init__(self):
        super(Net, self).__init__()
        self.conv1 = nn.Conv2d(1, 32, 3, 1)
        self.conv2 = nn.Conv2d(32, 64, 3, 1)
        self.dropout1 = nn.Dropout(0.25)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(9216, 128)
        self.fc2 = nn.Linear(128, 10)

    def forward(self, x):
        x = self.conv1(x)
        x = F.relu(x)
        x = self.conv2(x)
        x = F.relu(x)
        x = F.max_pool2d(x, 2)
        x = self.dropout1(x)
        x = torch.flatten(x, 1)
        x = self.fc1(x)
        Return x

def load_model(path):
    model = Net()
    model.load_state_dict(torch.load(path, map_location="cpu"))
    return model.eval()

def save_image(arr, path):
    im = Image.fromarray(arr)
    im.save(path)

def get_hash_sim(adv_hash, std_hash):
    cnt = 0
    for i in range(len(adv_hash[0])):
        tmp1 = adv_hash[0][i] > 0
        tmp2 = std_hash[0][i] > 0
        if tmp1 != tmp2:
            cnt += 1
    return 1 - (cnt / len(adv_hash[0]))

def cal_hash_bits(out):
    return out

def hex_hash(hash_bits):
    x = hash_bits.detach().numpy()
    res = [str(int(i > 0)) for i in x[0]]
    return hex(int(''.join(res), 2))
model = load_model("./model/convNet.pt")
target_image=torch.FloatTensor(np.load("mnist.n
pz")['test_images'][8583]).reshape(1,1,28,28)
target_out = model(target_image).detach()
target_nsgn=-torch.sign(target_out).detach()
image = torch.FloatTensor(np.load("mnist.npz")['test_images'][22]).reshape(1,1,28,28)
adv=Variable(image,requires_grad=True)

loss_f=nn.L1Loss()
loss_l2=nn.MSELoss()

def hex_hash(hash_bits):
    x = hash_bits.detach().numpy()
    res = [str(int(i > 0)) for i in x[0]]
    return hex(int(''.join(res), 2))


L0_THRES = 54.1
L2_THRES = 6.45
src = np.frombuffer(base64.b64decode(
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5eTkPgAAgD/l5GQ+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOPiYj8A AIA/5eRkPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOno6D0AAIA/5eTkPgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADl5OQ+AACAP62srD4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA Ax8ZGPwAAgD/p6Og9AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA6ejoPQAAgD/j4mI/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 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'),
                    dtype="float32")


def hash_buf(buf):
    global src
    arr = np.frombuffer(buf, dtype="float32")
    if arr.shape[0] != 28 * 28:
        raise BufferError("hacker")
    arr = np.clip(arr, 0, 1)
    diff = arr - src
    print(np.linalg.norm(diff, 0), np.linalg.norm(diff, 2))
    if np.linalg.norm(diff, 0) > L0_THRES or np.linalg.norm(diff, 2) > L2_THRES:
        raise BufferError("attack failed")
    arr = torch.FloatTensor(arr).reshape(1, 1, 28, 28)
    # need=0x1046822029745355ca048937f624fb87
    # hash(src)=0x91460a702d62d166a9942cb7fc10d7a2
    return hex_hash(model(arr))

def getsha256(s):
    sha256=hashlib.sha256()
    sha256.update(str(s).encode('utf-8'))
    ans=sha256.hexdigest()
    Return ans

def attack():
    global adv
    # load model, seed, image
    max_sim = 0
    cnt = 0
    loss_cnt = 0
    losses = []
    lr=0.1
    RATIO=10
    itercnt=0
    best = 9999
    best_l0 = 9999
    best_l2 = 9999
    save_image(image.squeeze().detach().numpy(), 'origion.tiff')
    save_image(target_image.squeeze().detach().numpy(), 'target.tiff')
    for i in range(10000):
        adv_out=model(adv)
        l1l=loss_f(adv,image)*RATIO
        hashl=torch.sum(F.relu(target_nsgn*adv_out))
        l2l=loss_l2(adv,image)
        loss=l1l+hashl
        loss.backward()
        adv.requires_grad=False
        data1 = adv.squeeze().detach().numpy().astype("float32").tobytes()
        arr1 = np.frombuffer(data1, dtype="float32")
        arr1 = np.clip(arr1, 0, 1)
        diff = arr1 - src
        a,b=(np.linalg.norm(diff, 0), np.linalg.norm(diff, 2))
        if hex_hash(adv_out)==hex_hash(target_out) and a< L0_THRES and b < L2_THRES:
            save_image(adv.squeeze().detach().numpy(), 'collision_pic.tiff')
            data = adv.squeeze().detach().numpy().astype("float32").tobytes()
            print(hash_buf(data))
            r = remote("175.27.158.159", "59101")
            context(log_level='debug')
            tmpstr = r.recvline().decode().replace('\n', '')
            sha_ans = tmpstr[45:109]
            sha_str = tmpstr[12:40]
            print(sha_str)
            print(sha_ans)
            print(tmpstr)
            prefix = ''
            flag = False
            ss = string.ascii_letters
            for i in ss:
                if (flag):
                    break
                for j in ss:
                    if (flag):
                        break
                    for k in ss:
                        if (flag):
                            break
                        for l in ss:
                            xxxx = i + j + k + l
                            if (sha_ans == getsha256(xxxx + sha_str)):
                                prefix = xxxx
                                print('in')
                                flag = True
                                break
            print(prefix)
            r.recvline()
            r.sendline(prefix)
            tt = r.recvline().decode().replace('\n', '')
            print(tt)
            r.sendline(base64.b64encode(data))
            r.interactive()
            exit(0)
        adv=adv-adv.grad*lr
        adv=adv.clamp(0,1)
        update = f"Iteration #{i}: l1={l1l} l2loss={l2l} hashloss={hashl}"
        print(update)
        print(hex_hash(adv_out))
print(hex_hash(target_out))
        print("diffcount",torch.sum(torch.abs(adv-image)>0.005))
        print(f"l0 loss: {torch.sum(adv!=image)}")
        print("best ", best)
        print(f"best_l0: {best_l0}")
        print(f"best_l2: {best_l2}")
        If hex_hash(adv_out)==hex_hash(target_out):
            best=min(best,torch.sum(torch.abs(adv-image)>0.005).numpy())
            best_l0=min(best_l0,torch.sum(adv!=image).numpy())
            best_l2 = min(best_l2, l2l)
            itercnt+=1
            mask=(torch.abs(adv-image)<np.clip(0.02+0.04*itercnt,0.02,0.4)).type(torch.FloatTensor)
            adv=adv*(1-mask)+image*mask
        adv.requires_grad = True
    save_image(adv.squeeze().detach().numpy(), 'collision_pic.tiff')
if __name__ == "__main__":
    attack()
```

It is not difficult to see in exp` that the main algorithm of this attack code is `FGSM`:

```python
adv = adv - adv.grad * lr
adv = adv.clamp(0,1)
```

The function of `FGSM` in the code is to make the `hash` of the false image more similar to the target`hash`, because the image gradient in the code is obtained by calculating `target_nsgn` (target feature layer, set to `-1` when it is less than or equal to `0`, and `0` is `1` when it is less than or equal to `0`) and `adv_out` of the attack image. Using `FGSM` can make the image move along the gradient in the same direction as the `hash` value of the two feature layers, so the final `hash` value of the attack image is the same as the target`hash`.

<div align=center><img src="./images/9.png"></div>

Let’s take a look at the design of the loss function for the `hash` value in `exp`. Here we multiply two `hash`, one of the `hash` is first multiplied by `-1`, and then use the activation function `relu` to screen out the same bits of the symbol and then sum it. Because the loss function is `0`, the `hash` value of the attack image and the target `hash` value are exactly the same, so this loss function can effectively move the `hash` value of the attack image toward the target `hash`.

```python
adv_out=model(adv)
l1l=loss_f(adv,image)*RATIO
hashl=torch.sum(F.relu(target_nsgn*adv_out))
l2l=loss_l2(adv,image)
loss=l1l+hashl
```

Next, let’s take a look at how to solve the problems of `l0` and `l2`. `l0` serves to constrain how many pixels to change, while `l2` serves to constrain the similarity of the two graphs. Therefore, the `l1` loss function `nn.L1Loss()` can be used to constrain `l0` (this is because `numpy` calculates that `l0` is the norm of `sum(x!=0)`), and `nn.MSEloss()` is used to constrain `l2`.

Set the initial attack image to the `Base64` encoded image given in the title, but since the loss function range and `FGSM` are performed on the entire image, the generated attack image is often slightly different from the comparison image in many pixel values, which will make it difficult to pass the hard `l0` constraint. Therefore, a heuristic hard `mask` is used in `exp` to solve this problem. Under the premise that the `hash` values ​​are equal, this `mask` will screen the pixels in the attack image whose difference between the contrast image is less than the threshold `sita=np.clip(0.02+0.04*itercnt, 0.02, 0.4)] and replace it with the pixel value of the contrast image to reduce the `l0` value. The heuristic is reflected in the `mask`'s `sita` threshold continues to grow as the number of iterations increases, Ultimately no greater than `0.4`, which will encourage attack pixels with fewer numbers of images but with a greater impact on the `hash` value, thus reducing `l0` and `l2`.

```python
mask=(torch.abs(adv-image)<np.clip(0.02+0.04*itercnt,0.02,0.4)).type(torch.FloatTensor)
adv=adv*(1-mask)+image*mask
```

## TJUCTF Freshman Competition Simple FGSM
Question description: I used `LeNet` to train a binary classification network (`4` and `7` in `mnist`). I will give you the trained network `target.pt` and a base64 encoding of the original image `4`. You need to generate an image so that it will mistakenly think that it is a `7` when satisfying the `L1` and `L2` constraints in the Check` function. Let's take a look at the code first:

```python
from base64 import b64decode
from torch import nn
import torch.nn.functional as func
import numpy as np
import torch
import os

class LeNet(nn.Module):
    def __init__(self,dimy):
        super(LeNet,self).__init__()
        self.conv1=nn.Conv2d(3,6,5)
        self.conv2=nn.Conv2d(6,16,5)
        self.linear1=nn.Linear(256,120)
        self.linear2=nn.Linear(120,84)
        self.linear3=nn.Linear(84,10)
        self.linear4=nn.Linear(10,dimy)

    def forward(self,x):
        x=func.relu(self.conv1(x))
        x=func.max_pool2d(x,2)
        x=func.relu(self.conv2(x))
        x=func.max_pool2d(x,2)
        x=x.view(x.size(0),-1)
        x=func.relu(self.linear1(x))
        x=func.relu(self.linear2(x))
        x=self.linear3(x)
        x=torch.sigmoid(self.linear4(x))
        Return x

mymodal=torch.load('./target.pt')
mymodal.eval()

base64_src='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAuLjoPwAAACAeHs4/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgGRnJPwAAAIB+fu4/AAAAIBUVxT8 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAgEBCAPwAAAGBXV+c/AAAAoJ2d7T8AAAAgFRW1PwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODQ0OA/AAAA4NTU1D8AAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAWFtY/AAAAwLq66j8AAAAgGhq6PwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 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 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgFBSkPwAAACAeHq4/AAAAOJKSwj8AAACglpbWPwAAAKCWltY/AAAAOJiY6D8AAABAPj7uPwAAACAREcE/AAAAIBQUlD8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAtLTk PwAAAEA9Pe0/AAAAIBAQsD8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMC0tOQ/AAAAAPLx4T8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4NbW1j8AAACgl5fnPwAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAADg1tbWPwAAAEA9Pe0/AAAAIBERwT8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAUFLQ/AAAA4N/f7z8AAACgnp7OPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBAQkD8AAABA OjrqPwAAAIB7e+s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODa2to/AAAA4NTU5D8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMC4uOg/AAAAIB4ezj8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAZGck/AAAAgH5+7j8AAAAgFRXFPwAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAQ EIA/AAAAYFdX5z8AAACgnZ3tPwAAACAVFbU/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4NDQ4D8AAADg1NTUPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBYW1j8AAADAurrqPwAAACAaGro/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAMDD gPwAAAGBVVeU/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgEBDgPwAAACAeHt4/AAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAODW1tY/AAAAQDo66j8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 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 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMC0tOQ/AAAAQD097T8 AAAAgEBCwPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwLS05D8AAAAA8vHhPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADg1tbWPwAAAKCXl+c/AAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAODW1tY/AAAAQD097T8AAAAgERHBPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBQUtD8AAADg39/vPwAAAKCens4/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgEBCQPwAAAEA6Ouo/AAAAgHt 76z8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4Nra2j8AAADg1NTkPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwLi46D8AAAAgHh7OPwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIBkZyT8AAACAfn7uPwAAACAVFcU/AAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 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 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAADg2traPwAAAODU1OQ/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
src= np.frombuffer(b64decode(base64_src),dtype="float64")
src=np.clip(src, 0, 1)

def Check(buf):
    L1_THRES=12.0
    L2_THRES=1.0
    global src
    arr = np.frombuffer(buf, dtype="float64")
    if arr.shape[0] != 3 * 28 * 28:
        raise BufferError("hacker")
    arr = np.clip(arr, 0, 1)
    diff = arr - src
    if np.linalg.norm(diff, 1) > L1_THRES or np.linalg.norm(diff, 2) > L2_THRES:
        raise BufferError("attack failed")
    arr = torch.FloatTensor(arr).reshape(1, 3, 28, 28)
    return (mymodal(arr)<0.5).tolist()[0][0]

print(Check(b64decode(base64_src))))
```

### analyze
This question still examines the commonly used adversarial sample algorithm `FGSM`, similar to the simplified version of `N1CTF2021 Collision`.

### Solve the problem
Here we directly post the `exp` of the questioner `Alice`.

```python
from torch import nn
from torch.utils.data import Dataset,DataLoader
import torch.nn.functional as func
import numpy as np
import torch
from PIL import Image
import os
import base64
import random
from torchvision import transforms
from torch.autograd import Variable


class LeNet(nn.Module):
    def __init__(self,dimy):
        super(LeNet,self).__init__()
        self.conv1=nn.Conv2d(3,6,5)
        self.conv2=nn.Conv2d(6,16,5)
        self.linear1=nn.Linear(256,120)
        self.linear2=nn.Linear(120,84)
        self.linear3=nn.Linear(84,10)
        self.linear4=nn.Linear(10,dimy)
    def forward(self,x):
        x=func.relu(self.conv1(x))
        x=func.max_pool2d(x,2)
        x=func.relu(self.conv2(x))
        x=func.max_pool2d(x,2)
        x=x.view(x.size(0),-1)
        x=func.relu(self.linear1(x))
        x=func.relu(self.linear2(x))
        x=self.linear3(x)
        x=torch.sigmoid(self.linear4(x))
        Return x

class MyDataSet(Dataset):
    def __init__(self,datapath,trans=None):
        self.datapath=datapath
        self.trans=trans
        self.data=list()
        self.label_map={'4':0,'7':1}
        path1=datapath+'/4/'
        path2=datapath+'/7/'
        filest1=os.listdir(path1)
        flist2=os.listdir(path2)
        for i in range(len(filist1)):
            tmppath=path1+filist1[i]
            tmpimg = Image.open(tmppath).convert('RGB')
            if (self.trans != None):
                tmpimg = self.trans(tmpimg)
            self.data.append((tmpimg, 1.0))
        for i in range(len(flist2)):
            tmppath=path2+flist2[i]
            tmpimg = Image.open(tmppath).convert('RGB')
            if (self.trans != None):
                tmpimg = self.trans(tmpimg)
            self.data.append((tmpimg, 0.36))

    def __len__(self):
        return len(self.data)

    def __getitem__(self, item):
        return self.data[item][0],self.data[item][1]

def set_seed(seed=0):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed(seed)

def save_image(arr, path):
    im = Image.fromarray(arr)
    im.save(path)

atk_trans=transforms.Compose([transforms.ToTensor()])

mainpath="./database/mnist/"
atkpath=os.path.join(mainpath,"atk")
atk_data=MyDataSet(atkpath,atk_trans)
batch_size=1
atk_load=DataLoader(atk_data,batch_size=batch_size,drop_last=True)

mymodal=torch.load('./database/target.pt')
mymodal.train()
tmpans=0
image=0
cnt=0
for _, data in enumerate(atk_load):
    images, ans = data
    if(cnt==1):
        tmpans = ans.float()
    if(cnt==0):
        image=images
    cnt += 1

src=image.squeeze().detach().flatten().numpy().astype("float64")
src=np.clip(src, 0, 1)

picpath=mainpath+'/atk/4/mnist_test_24.png'
adv=Variable(image,requires_grad=True)
loss_f=nn.L1Loss()
loss_l2=nn.MSELoss()
lr=0.1
RATIO=1.0
epoch=1000
print("before atk: ",mymodal(adv))
print(mymodal(adv))

for i in range(epoch):
    y=mymodal(adv)
    l1l = loss_f(adv, image) * RATIO
    l2l = loss_l2(y,tmpans)
    loss = l1l+l2l
    loss=loss
loss.backward()
    adv.requires_grad = False
    data1 = adv.squeeze().detach().numpy().astype("float64").tobytes()
    arr1 = np.frombuffer(data1, dtype="float64")
    arr1 = np.clip(arr1, 0, 1)
    diff = arr1 - src
    a, b = (np.linalg.norm(diff, 1), np.linalg.norm(diff, 2))
    if(i==epoch-1):
        print(a,' --------------------> ',b)
    adv = adv - adv.grad * lr
    adv = adv.clamp(0, 1)
    adv.requires_grad = True

print("after atk: ",mymodal(adv))
ans=adv.squeeze().detach().flatten().numpy().astype("float64")
ans=np.clip(ans, 0, 1)
ans=base64.b64encode(ans.tobytes())


from pwn import *
r=remote('0.0.0.0',9998)
r.recvuntil(b'> \n')
r.sendline(ans)
flag=r.recvline()
print(bytes.decode(flag))
r.interactive()
```

# refer to
 - [Explaining and Harnessing Adversarial Examples](https://arxiv.org/abs/1412.6572)

 - [N1CTF2021 Collision exp](https://github.com/Nu1LCTF/n1ctf-2021/blob/main/Misc/collision/exp.py)

 - [N1CTF2021 Collision exp parsing write up](https://blog.csdn.net/qq_42940521/article/details/121510845)

 - [TJUCTF Freshman Competition-AI Security Column write up](https://blog.csdn.net/qq_42940521/article/details/122664019)