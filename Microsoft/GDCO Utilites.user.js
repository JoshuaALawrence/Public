// ==UserScript==
// @name         GDCO Utilites
// @version      0.2
// @description  Utilities that help day-to-day operation.
// @author       Joshua Lawrence - ZT Systems - v-jolawrence@microsoft.com
// @match        https://gdcoapp.trafficmanager.net/tasks/details/*
// @grant        GM_xmlhttpRequest
// ==/UserScript==

(function() {
    'use strict';
    let Searching = false;
    const popupStyle = document.createElement('style');
    popupStyle.textContent = `
        .popup-container {
            position: fixed;
            z-index: 9999;
            background-color: white;
            border: 1px solid #ccc;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            padding: 10px;
            border-radius: 5px;
            font-family: Arial, sans-serif;
        }
        .popup-table {
            width: auto;
            border-collapse: collapse;
            margin-top: 5px;
        }
        .popup-table th, .popup-table td {
            padding: 8px;
            border-bottom: 1px solid #ddd;
        }
        .popup-table th {
            text-align: left;
            background-color: #f2f2f2;
        }
    `;
    document.head.appendChild(popupStyle);

    function showPopup(dataArrays, mouseX, mouseY) {
        const popupContainer = document.createElement('div');
        popupContainer.className = 'popup-container';
        popupContainer.style.top = (mouseY - 30) + 'px';
        popupContainer.style.left = (mouseX - 30) + 'px';
    
        const table = document.createElement('table');
        table.className = 'popup-table';
    
        const headers = ['Name', 'Asset Tag', 'Serial', 'Location', 'Rack', 'Side', 'Slot'];
    
        // Create header row
        const headerRow = document.createElement('tr');
        headers.forEach(headerText => {
            const th = document.createElement('th');
            th.textContent = headerText;
            headerRow.appendChild(th);
        });
        table.appendChild(headerRow);
    
        // Create data rows
        dataArrays.forEach(rowData => {
            const row = document.createElement('tr');
            rowData.forEach(cellData => {
                const td = document.createElement('td');
                td.textContent = cellData;
                row.appendChild(td);
            });
            table.appendChild(row);
        });
    
        popupContainer.appendChild(table);
        document.body.appendChild(popupContainer);
    
        // Close popup if click outside
        document.addEventListener('click', function(event) {
            if (popupContainer && !popupContainer.contains(event.target) && document.body.contains(popupContainer)) {
                document.body.removeChild(popupContainer);
            }
        });
    }
    
    document.addEventListener('mouseup', async function(event) {
        const selection = window.getSelection();
        if (selection && selection.toString() !== '' && !Searching) {
            const windowTitle = document.title;
            const targetElement = event.target;
            const highlightedText = selection.toString().trim();
            const nameMatches = highlightedText.match(/(DS?M\d+\w*-\d+-\d+-\d+\w+\d*|\w+\d+\.ds?m\d+|ds?m\d+-\d+-\d+x?omt)/gi);
            let data = null;
    
            // If a popup already exists, do not open another one
            if (document.querySelector(".popup-container")) {
                return;
            }
    
            // Do not trigger if selecting inside the popup
            if (targetElement.closest(".popup-container")) {
                return;
            }
    
            // Notify the user it's searching
            document.title = "Searching...";
            Searching = true;
    
            // Array to hold unique results
            let uniqueData = [];
    
            // Search based on Name matches
            if (nameMatches && nameMatches.length > 0) {
                for (const nameMatch of nameMatches) {
                    data = await search("(Name eq '" + nameMatch + "')");
                    if (data && data.value?.length > 0) {
                        // Add unique entries based on 'Name' field
                        data.value.forEach(item => {
                            if (!uniqueData.some(uniqueItem => uniqueItem.Name === item.Name)) {
                                uniqueData.push(item);
                            }
                        });
                    }
                }
            } else if (targetElement.classList.contains('divided-item') && targetElement.innerHTML.match(/Tag/)) {
                // Search based on AssetTag if no Name matches found
                data = await search("(search.in(AssetTag,'" + highlightedText + "'))");
                if (data && data.value?.length > 0) {
                    uniqueData = data.value;
                }
            }
    
            // Only popup if there's data
            if (uniqueData.length > 0) {
                const rowData = uniqueData.map(item => [
                    item.Name,
                    item.AssetTag,
                    item.SerialNumber,
                    item.Location,
                    item.Rack,
                    item.Side,
                    item.SlotNumber
                ]);
                showPopup(rowData, event.clientX, event.clientY);
            }
    
            // Reset the title and searching flag
            document.title = windowTitle;
            Searching = false;
        }
    });
    
    function searchLocalStorageByRegex(regex) {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (regex.test(key)) {
                return localStorage.getItem(key);
            }
        }
        return null;
    }

    function getToken() {
        const regex = /authority.*?microsoftonline\.com\/microsoft\.onmicrosoft.com.*?https\:\/\/mcio\.microsoft\.com\/gdcoservice\/\.default/; // Regular expression to match the key
        const value = JSON.parse(searchLocalStorageByRegex(regex)).accessToken;
        return value;
    }

    function search(filter = "", search = "") {
        return new Promise((resolve, reject) => {
            const Token = getToken();
            if (Token) {
                GM_xmlhttpRequest({
                    method: 'POST',
                    url: 'https://hwinventory.trafficmanager.net/Inventory/v2/search',
                    headers: {
                        'Accept': 'application/json, text/plain, */*',
                        'Accept-Encoding': 'gzip, deflate, br, zstd',
                        'Accept-Language': 'en-US,en;q=0.9',
                        'Authorization': 'Bearer ' + Token,
                        'Origin': 'https://gdcoapp.trafficmanager.net',
                        'Referer': 'https://gdcoapp.trafficmanager.net/',
                        'Content-Type': 'application/json'
                    },
                    data: JSON.stringify({
                        select: '*',
                        search: search,
                        filter: filter,
                        orderby: '',
                        count: true,
                        queryType: 'full',
                        top: 500,
                        skip: 0
                    }),
                    onload: function(response) {
                        if (response.status === 200) {
                            const data = response.responseText;
                            resolve(JSON.parse(data));
                        } else {
                            console.error('Request failed with status:', response.status);
                            reject(null);
                        }
                    },
                    onerror: function(error) {
                        console.error('There was a problem with the request:', error);
                        reject(null);
                    }
                });
            } else {
                reject(null);
            }
        });
    }

})();
