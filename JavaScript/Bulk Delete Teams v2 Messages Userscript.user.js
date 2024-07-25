// ==UserScript==
// @name         Teams Bulk [Delete]
// @namespace    http://tampermonkey.net/
// @version      2024-07-25
// @description  Hold 'Delete' for 5 seconds to remove all messages by you in the chat.
// @author       Joshua Lawrence
// @match        https://teams.microsoft.com/v2/
// @icon         https://www.google.com/s2/favicons?sz=64&domain=microsoft.com
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // HOW-TO:
    // Start: Hold Delete for 5 Seconds
    // Stop: Hold Delete for 5 Seconds

    let Name = ""
    let isRunning = false;
    let deleteKeyTimer;
    let deleteKeyHoldTime = 5000;
    let foundMessage = false;
    let totalWipedMessages = 0;
    let deletedMessages = 0;

    function triggerRightClick(element) {
        let event = new MouseEvent('contextmenu', {
            bubbles: true,
            cancelable: true,
            view: window
        });
        element.dispatchEvent(event);
    }

    function showMessage(message) {
        if (document.getElementById("AlertBox")) { document.getElementById("AlertBox").remove() }
        let messageBox = document.createElement('div');
        messageBox.id = "AlertBox"
        messageBox.textContent = message;
        messageBox.style.position = 'fixed';
        messageBox.style.bottom = '20px';
        messageBox.style.right = '20px';
        messageBox.style.backgroundColor = 'rgba(0,0,0,0.75)';
        messageBox.style.color = 'white';
        messageBox.style.padding = '10px';
        messageBox.style.borderRadius = '5px';
        messageBox.style.zIndex = '10000';
        document.body.appendChild(messageBox);
        setTimeout(() => {
            if (messageBox) {
                messageBox.remove();
            }
        }, 5000);
    }

    async function deleteMessages() {
        while (isRunning) {
            let messages = Array.from(document.querySelectorAll('div[data-tid="chat-pane-item"]'))
            .filter(message => {
                let authorElement = message.querySelector('span[data-tid="message-author-name"]');
                return authorElement && authorElement.textContent.includes(Name);
            })
            .reverse();
            if (messages.length === 0) {
                if (foundMessage) {
                    showMessage("No messages, waiting 15 seconds before scrolling due to Microsoft rate limiting.");
                    await new Promise(resolve => setTimeout(resolve, 1000));
                    for(let i = 15; i>0;i--) {
                        showMessage(`Waiting ${i} more second(s) before scrolling`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                    }
                    showMessage(`Continuing`);
                } else {
                    showMessage("Looking for messages..");
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
                foundMessage = false;
                let topmostMessage = document.querySelector('div[data-tid="chat-pane-item"]');
                if (topmostMessage) {
                    topmostMessage.scrollIntoView({ behavior: 'smooth', block: 'start' });
                } else {
                    showMessage("No messages available to scroll to, stopping.");
                    stopScript();
                    break;
                }
                await new Promise(resolve => setTimeout(resolve, 500));
                continue;
            }


            for (let message of messages) {
                if (!isRunning) break;
                if (deletedMessages % 10 == 0 && deletedMessages > 0) {
                    for(let i = 10; i>0;i--) {
                        showMessage(`Waiting ${i} second(s) before scrolling to avoid throttling`);
                        await new Promise(resolve => setTimeout(resolve, 1000));
                        deletedMessages = 0;
                    }
                    showMessage(`Continuing`);
                }
                message.scrollIntoView({ behavior: 'auto', block: 'center' });
                await new Promise(resolve => setTimeout(resolve, 200));
                let messageBody = message.querySelector('div[data-tid="chat-pane-message"]');
                if (messageBody) {
                    triggerRightClick(messageBody);
                    await new Promise(resolve => setTimeout(resolve, 300));
                    let deleteOption = document.querySelector('div[role="menuitem"][aria-label="Delete this message"]');
                    if (deleteOption) {
                        deleteOption.click();
                        totalWipedMessages++;
                        deletedMessages++;
                        foundMessage = true
                        showMessage(`Deleted ${totalWipedMessages} total messages.`);
                        await new Promise(resolve => setTimeout(resolve, 300));
                    } else {
                        console.error("Delete option not found.");
                    }
                }
            }
        }
    }

    function startScript() {
        if (!isRunning) {
            isRunning = true;
            deleteMessages();
        } else {
            showMessage("Script already running.");
        }
    }

    function stopScript() {
        if (isRunning) {
            isRunning = false;
            showMessage("Script stopped.");
        }
    }

    document.addEventListener('keydown', function(e) {
        if (e.key === 'Delete') {
            if (!deleteKeyTimer) {
                showMessage("Hold 'Delete' for 5 seconds to trigger the script.");
                deleteKeyTimer = setTimeout(() => {
                    if (!isRunning) {
                        startScript();
                    } else {
                        stopScript();
                    }
                }, deleteKeyHoldTime);
            }
        }
    });
    document.addEventListener('keyup', function(e) {
        if (e.key === 'Delete') {
            clearTimeout(deleteKeyTimer);
            deleteKeyTimer = null;
        }
    });
})();
