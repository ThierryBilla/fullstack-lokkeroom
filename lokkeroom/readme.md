My project is to create a full stack lokkeroom project, this project contains a pg db, a back-end in node express js and the front-end in react js. 

The goal of this project is to create a message app.

The first thing is to be able to sign up and log in and then fetch the chat list and message windows for the logged user.

The database is already deployed on Heroku. 

The back-end seems finish, sometimes it mays require some adaptations to make it works with the front-end but globaly the back-end seems strong enough.

--------------------------------------------------------------------------------------

What's remaining to do and what are the next steps ???

- Develop a modal for each pop up instead of using the browser prompt and alert pop up

- Debug messages in group lobbies. Currently the messages sent always appears on top of messages received when the browers is refreshed.

- Improve the layout of messages for messages in lobbies by adding some elements like user name, and date / hour of the message. Positioning messages bubbles on right and left and maybe adding an animation when a message is sent or received.

- Debugging the DM function, currently not fetching DM. Once it will be done, check if it needs some layout improvment like the messages in group lobbies.

- Add a log out button

- Deploy the back-end




- Once it will be done I'd like to add and improve some features. 

- Leave a lobbies
- invite someone in a lobby
- Kick or ban an user from a lobbies
- Show the list of people inside a lobby
- block a user messages
- Add a profile picture
- Rename a lobby
- Delete lobbies or DM from the list
- Responsive design
- Send picture ?






















[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-24ddc0f5d75046c5622901739e7c5dd533143b0c8e959d652212380cedb1ea36.svg)](https://classroom.github.com/a/aa-bw43K)
# Title: Lokkerroom Fullstack

- Type of Challenge: `Consolidation`
- Duration: `5 days`
- Deadline: `02/05/2024`
- Deployment strategy :
	- Github page
	- Heroku
	- Heroku + remote DBA

- Team challenge : `solo`


## The Mission
After having developed your very Own API with the lokkerroom challenge, it is time to actually code a frontend UI for it so that users from all over the world will be able to chat using your app.

## Mission objectives

- Your first objective will be of course to be sure that your backend is safely deployed Online. For that, I would really recommend that you use Heroku as you have access to some free resources in your `github Student pack`. The deployement part is half of this challenge. It is the first thing you should tackle so that you can work safely on your UI afterwards.

Note: If you are not sure about the quality of your backend code, you'll find provided in this repo the code of the simplified version of the chat app that I coded as part as the correction of the previous exercise. Feel free to use it as your backend if you want. (The code might need some adaptation in order to work ;))

- Once the backend App is deployed and you added the API documentation in the README (with the main endpoints and an example of request and/or response), time to switch to your trusty ReactJS. Create a new project (and another repo!), and use everything you've learned so far in order to create an UI for your chat app.

- Design wise, [check out these designs](https://www.pinterest.com/search/pins/?q=message%20chat%20UI%20desktop&rs=typed), choose one you like and adapt it to your needs, at the end of this challenge, I expect 30 diferent looking chats. We will review your designs at the end.


### Must-have features

- All the API routes from the lokkeroom challenge should be taken into account in your app, all the backend features should have their frontend counterparts.


### Miscellanous information

- NO EJS Files, you will work in silos. A backend server and a Frontend server communicating through fetch/axios.

- That means that I fully expect your ReactJS frontend app to be deployed online as well.


## Deliverables

1. Publish your source code on the GitHub repository.
2. Pimp up the README file:
	- What, Why, When, How, Who.
	- Pending things to do (roadmap).
	- It must contain a link to the "live" version. The "live" version must contain a link to the source code on GitHub.
3. Publish the link to the "live" version on your startup's Discord's channel.


## Evaluation criterias

### Backend Deployment:

- Successfully deploying the backend API on Heroku or any other specified platform.
- Ensuring the backend is accessible and operational online.
- Handling any necessary configurations for security and performance.
- A README with the main endpoints and an example of request and/or response (you can check the tool swagger but it's not required).

### Frontend Implementation:

- Creating a responsive and user-friendly UI using ReactJS.
- Integrating all API routes from the backend into the frontend application.
- Implementing necessary features like user authentication, sending and receiving messages, displaying chat history, etc.
- Ensuring smooth communication between frontend and backend through fetch or any other suitable method.

### Design and User Experience:

- Adapting and customizing a chosen design from the provided inspirations to create a unique chat UI.
- Ensuring the UI is intuitive, visually appealing, and easy to navigate for users.

### Code Quality and Structure:
- Writing clean, well-structured, and maintainable code in both backend and frontend.
- Following best practices and conventions for ReactJS development.
- Handling errors gracefully and implementing proper error handling mechanisms.

### Documentation:
- Creating a comprehensive README file in the frontend GitHub repository, covering what, why, when, how, and who aspects of the project.
- Clearly stating any pending tasks or future improvements.
- Providing a link to the live version of the application and linking back to the GitHub repository.

### Bonus:
- Implementing additional features beyond the minimum requirements.
- Demonstrating creativity, innovation, or problem-solving skills in the project.
- Going above and beyond in design, functionality, or deployment strategies.
- Effectively utilizing any additional resources or technologies beyond the provided specifications.




## A final note of encouragement

This will be your first "real" fullstack app online, so give your everything! Working in teams and pair-coding is always encouraged.

![You've got this!](http://78.media.tumblr.com/f9247799ae2fe6613f643957020101c6/tumblr_inline_n80n8u8pSz1sbdww6.gif)
