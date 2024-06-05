## osu!gaming CTF 2024 - ecs!catch

We are given a zip file containing a game which seems like an imitation of the osu!catch game mode. 

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/1378a184-b632-44da-a41b-2625908b6d9a)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4a0e5637-1da2-4436-88f3-b57d21b9ac7c)
There are 3 available songs.

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/cfc9dbbe-3782-4309-83eb-f6819d4e7f08)
Game is pretty straightforward, we control the character to catch falling fruits. I completed the first 2 levels with full combo.
I tried to get full-combo on the 3rd song, but towards the middle of the song, the game becomes impossible to win.

One thing we know is that the game is run using Unity Engine, which means the game is probably written in C#.
C# compiles to an intermediate language, which is interpreted by an execution engine. We can use dnSpy to interpret the IL code and convert them to translate them back to C# code.

Unity games usually compile all scripts into Assembly-CSharp.dll in the Managed folder within the game's data directory. I loaded this file using dnSpy.

Let's try to find the winning condition. 
Under the '-' namespace, we can see a list of user-defined classes.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/bd423758-ccb7-420d-8017-f65c045a56f3)

The GameManager class handles the user's score, setter methods to update notes hit and missed, user health, and some other stuff. There is a function SendGameResults which calls CreateGameResultsRequest to craft a POST request to `https://ecs-catch.web.osugaming.lol`. 
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/090b572b-e066-4ff9-8b96-356081396340)
Our score after finishing a level is converted to JSON and sent to the server. The response from the server is then checked if it contains the flag format `osu{`. Looking at the function which called SendGameResults, results is an object containing the display score, currenct combo, total accumulated, hit fruits, hit droplets, and total missed.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/e742e83c-0a74-4970-82e8-369dbae86f35)

![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/b8382468-417a-4896-b8e0-8fea15524f4d)
Information about the third song is given to us (how many fruits and droplets), and I can calculate the display score, totalAcc, combo easily, forge a request to the server where I get a full combo and maximum points.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/d17a0070-e202-4556-acc9-d84b022f0226)

But I went with another approach, and thought about modifying missed notes to count as hits (even though it might be easier to just forge the request). Under the NoteObject class, the OnTriggerEnter2D function calls the note hit functions in GameManager, which increments our points. This function is triggered when our player object tagged 'Activator' collides with the different gameObjects tagged as Fruit, Hyperfruit, Clapfruit, Drop or Droplets.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/4a60f76d-c897-4bad-8e5a-0ac0be03021c)

Under the same class, there is an OnTriggerExit2D function which invokes the NoteMissed function, which is triggered when our player object misses the fruits and the notes exit the trigger area (screen)? 
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/f617d3fe-b4e8-4b40-8d1c-cb411a271688)

We can try to patch OnTriggerExit2D to have to same functionality as OnTriggerEnter2D, such that every note that exits the trigger area still counts as a hit.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/e4ed35e4-27fc-4294-9071-adaad4d897d3)

Before recompiling, we can also increase the speed of the game by modifying the initialization function in the BeatScroller class, to divide beatTemp with 5 instead of 60.
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/c0d29a21-70f3-42d2-b6ea-f4a083100322)

Let's rerun the third level in game!
![image](https://github.com/jiayuchann/jiayuchann.github.io/assets/58498244/ad184135-08e2-4495-8518-de3ab0614860)
`osu{h0pefu11y_th1s_4ss1gnm3nt_g3ts_m3_an_A}`
