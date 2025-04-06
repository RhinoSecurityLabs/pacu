document.addEventListener('DOMContentLoaded', () => {
    fetch('data/report.json')
        .then(response => response.json())
        .then(data => {
            const moduleStatus = {};
            const resourcesFound = {};
            const errorMessages = {};
            let errorCount = 0;
            let successCount = 0;

            data.forEach(item => {
                // Determinar o status do módulo
                if (item.stderr) {
                    errorCount++;
                    moduleStatus[item.module] = 'Error';
                    errorMessages[item.module] = item.stderr.trim();
                } else {
                    successCount++;
                    moduleStatus[item.module] = 'Success';
                }

                // Verificar se foram encontrados recursos ou ARNs
                const foundResources = item.stdout.match(/(\d+) (function|instance|group|resource|database|bucket|cluster|volume)\(s\) found/gi);
                const foundArns = item.stdout.match(/arn:aws:[^:\s]+:[^:\s]+:[^:\s]+:[^\s]+/g);

                // Adicionar funções encontradas mencionadas no módulo
                const lambdaFunctions = item.stdout.match(/Enumerating data for ([^\n]+)/g);

                if (foundResources || foundArns || lambdaFunctions) {
                    resourcesFound[item.module] = [
                        ...(foundResources || []),
                        ...(foundArns || []),
                        ...(lambdaFunctions ? lambdaFunctions.map(fn => fn.replace('Enumerating data for ', 'Function: ')) : [])
                    ];
                }
            });

            const totalModules = Object.keys(moduleStatus).length;

            document.getElementById('module-count').textContent = totalModules;
            document.getElementById('success-count').textContent = successCount;
            document.getElementById('error-count').textContent = errorCount;

            displayModuleTable(moduleStatus, resourcesFound, errorMessages);
            createChart(totalModules, successCount, errorCount);
        });

    // Carregar e exibir os detalhes dos recursos ao clicar no botão
    document.getElementById('toggle-resources').addEventListener('click', () => {
        fetch('data/aws_resources.json')
            .then(response => response.json())
            .then(data => {
                const resourceDetails = document.getElementById('resource-details');
                const resourceTable = document.getElementById('resource-table').getElementsByTagName('tbody')[0];

                resourceTable.innerHTML = ''; // Limpar a tabela antes de preencher

                for (const [resourceType, identifiers] of Object.entries(data)) {
                    let row = document.createElement('tr');

                    let cellType = document.createElement('td');
                    cellType.textContent = resourceType;
                    row.appendChild(cellType);

                    let cellIdentifiers = document.createElement('td');
                    cellIdentifiers.innerHTML = identifiers.join('<br>');
                    row.appendChild(cellIdentifiers);

                    resourceTable.appendChild(row);
                }

                resourceDetails.style.display = 'block'; // Exibir a seção de detalhes dos recursos
            })
            .catch(error => {
                console.error('Erro ao carregar o arquivo JSON:', error);
            });
    });
});

function displayModuleTable(moduleStatus, resourcesFound, errorMessages) {
    let moduleTbody = document.getElementById('module-tbody');
    for (let moduleName in moduleStatus) {
        let row = document.createElement('tr');

        let cellStatus = document.createElement('td');
        cellStatus.textContent = moduleStatus[moduleName];
        cellStatus.className = moduleStatus[moduleName] === 'Error' ? 'status-error' : 'status-success';
        row.appendChild(cellStatus);

        let cellName = document.createElement('td');
        cellName.textContent = moduleName;
        row.appendChild(cellName);

        let cellResources = document.createElement('td');
        if (resourcesFound[moduleName]) {
            cellResources.textContent = "See details below";
        } else {
            cellResources.textContent = "None";
        }
        row.appendChild(cellResources);

        moduleTbody.appendChild(row);

        // Adicionar linha de erro, se houver
        if (moduleStatus[moduleName] === 'Error') {
            let errorRow = document.createElement('tr');
            let errorCell = document.createElement('td');
            errorCell.colSpan = 3; // Ocupa todas as colunas restantes
            errorCell.textContent = `Error: ${errorMessages[moduleName]}`;
            errorCell.className = 'error-message';
            errorRow.appendChild(errorCell);
            moduleTbody.appendChild(errorRow);
        }

        // Adicionar linha de recursos, se houver
        if (resourcesFound[moduleName]) {
            let resourcesRow = document.createElement('tr');
            let resourcesCell = document.createElement('td');
            resourcesCell.colSpan = 3; // Ocupa todas as colunas restantes
            resourcesCell.innerHTML = resourcesFound[moduleName].join("<br>");
            resourcesCell.className = 'resources-message';
            resourcesRow.appendChild(resourcesCell);
            moduleTbody.appendChild(resourcesRow);
        }
    }
}

function createChart(totalModules, successCount, errorCount) {
    const ctx = document.getElementById('module-chart').getContext('2d');
    const data = {
        labels: ['Total Modules', 'Total Successes', 'Total Errors'],
        datasets: [{
            label: 'Count',
            data: [totalModules, successCount, errorCount],
            backgroundColor: ['rgba(0, 123, 255, 0.5)', 'rgba(75, 192, 192, 0.5)', 'rgba(255, 99, 132, 0.5)'],
            borderColor: ['rgba(0, 123, 255, 1)', 'rgba(75, 192, 192, 1)', 'rgba(255, 99, 132, 1)'],
            borderWidth: 1
        }]
    };

    const config = {
        type: 'bar',
        data: data,
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    };

    new Chart(ctx, config);
}
