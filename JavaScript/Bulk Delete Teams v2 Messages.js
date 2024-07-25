// This script deletes all messages from the user
// in the current chat, and scrolls up automatically.

// HOW-TO:
// 1. Open https://teams.microsoft.com/
// 2. Open dev settings (f12/ctrl+shift+i)
// 3. If it asks you to, type 'allow pasting'
// 4. Select the channel you want to delete in
// 5. Paste the script into the console and wait

// NOTE: 
// IF IT LAGS, OR IT DOES NOT DELETE THE MESSAGE BUT OPENS THE MENU
// RAISE THE WAIT TIME BETWEEN RIGHT CLICK AND DELETE

// Use the name it shows for your personal profile
// if it has (EXT) keep it in the display name.
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
