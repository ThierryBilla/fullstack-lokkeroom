const fetchAllMessages = () => {

	fetch("https://lokker-app-3e7764e2f09c.herokuapp.com/api/messages", {
	      method: "GET",
	      headers: {
	        "Content-Type": "application/json",
	        "Authorization": `Bearer ${localStorage.getItem("token")}`
	      }
	    })
	.then((response) => {
		if(response.status === 403){
			alert("please log in to access the chat")
			window.location.href = "/"
		}else {
			return response.json()
		}
	})
	.then((data) => {
		data.forEach((msg) => {
			document.querySelector('.chatBox').insertAdjacentHTML('afterbegin', `<div class="message">${msg.content}</div>`)

		})

	})
}


fetchAllMessages()


const newMessageForm = document.getElementById('newMessage')
newMessageForm.addEventListener('submit', (event) => {
	event.preventDefault()
	const content = event.target.children[0].value

	fetch('https://lokker-app-3e7764e2f09c.herokuapp.com/api/messages/new', {
	      method: "POST",
	      headers: {
	        "Content-Type": "application/json",
	        "Authorization": `Bearer ${localStorage.getItem("token")}`
	      },
	      body: JSON.stringify({content: content}),
	    })
	.then(response => response.json())
	.then((data) => {
		console.log(data)
		document.querySelector('.chatBox').insertAdjacentHTML('afterbegin', `<div class="message">${content}</div>`)
		event.target.children[0].value = ""

	})

})