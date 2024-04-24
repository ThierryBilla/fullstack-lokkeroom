const registerForm = document.getElementById("registerform")
const loginForm = document.getElementById("loginform")


registerForm.addEventListener('submit', (event) => {
	event.preventDefault()
	console.log(event)
	const email = event.target.children[1].value
	const nickname = event.target.children[3].value
	const password = event.target.children[5].value
	console.log(email, nickname, password)

	fetch('https://lokker-app-3e7764e2f09c.herokuapp.com/api/auth/register', {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({email: email, nickname: nickname, password: password}),
    })
    .then(response => response.json())
    .then((data) => {
    	console.log(data)
    	alert('you succesfully created an user, please login to access the chat')
    })

	// fetch('https://lokker-app-3e7764e2f09c.herokuapp.com/test')
	// .then(response => response.json())
	// .then((data) => {
	// 	console.log(data)
	// })
})


loginform.addEventListener("submit", (event) => {
	event.preventDefault()
	const email = event.target.children[1].value
	const password = event.target.children[3].value

	console.log(email, password)
		fetch('https://lokker-app-3e7764e2f09c.herokuapp.com/api/auth/login', {
	      method: "POST",
	      headers: {
	        "Content-Type": "application/json",
	      },
	      body: JSON.stringify({email: email, password: password}),
	    })
	    .then(response => response.json())
	    .then((data) => {
	    	console.log(data)
	    	alert('you succesfully logged in')
	    	document.cookie = `token=${data.token}`
	    	localStorage.setItem("token", data.token);
	    })

})