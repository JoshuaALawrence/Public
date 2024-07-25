const Name = "DISPLAY NAME HERE";

function triggerRightClick(element) {
    let event = new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
        view: window
    });
    element.dispatchEvent(event);
}

async function deleteTeamsMessages() {
    while (true) {
        let messages = Array.from(document.querySelectorAll('div[data-tid="chat-pane-item"]'))
            .filter(message => {
                let authorElement = message.querySelector('span[data-tid="message-author-name"]');
                return authorElement && authorElement.textContent.includes(Name);
            })
            .reverse();

        if (messages.length === 0) {
            console.log("No more messages found, scrolling to the topmost message to load more...");

            let topmostMessage = document.querySelector('div[data-tid="chat-pane-item"]');
            if (topmostMessage) {
                topmostMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                console.log("No messages available to scroll to, stopping.");
                break;
            }

            await new Promise(resolve => setTimeout(resolve, 500));
            continue;
        }

        for (let message of messages) {
            message.scrollIntoView({ behavior: 'auto', block: 'center' });

            await new Promise(resolve => setTimeout(resolve, 200));

            let messageBody = message.querySelector('div[data-tid="chat-pane-message"]');
            triggerRightClick(messageBody);

            await new Promise(resolve => setTimeout(resolve, 300));

            let deleteOption = document.querySelector('div[role="menuitem"][aria-label="Delete this message"]');
            if (deleteOption) {
                deleteOption.click();
                await new Promise(resolve => setTimeout(resolve, 300));
            } else {
                console.error("Delete option not found.");
            }
        }
    }
}

deleteTeamsMessages();
