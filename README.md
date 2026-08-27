To run the MCP inspector locally use the following commands in VS Code
$env:NEO_MOCK_MODE = "true"
npx @modelcontextprotocol/inspector python "Neo MCP\neo_mcp_server.py"

You will see the mcp inspector launched as below
<img width="1918" height="900" alt="image" src="https://github.com/user-attachments/assets/42cef854-61b2-4307-9610-9497ce62ee5a" />

Click the "Tools" menu option in the top to get the list of mcp endpoints
<img width="1895" height="904" alt="image" src="https://github.com/user-attachments/assets/c3f21e44-7fa0-409d-983e-b165ae4b7450" />

click load_mock_scan endpoint and fill in the file path and source filter
<img width="1060" height="415" alt="image" src="https://github.com/user-attachments/assets/3746e63d-bd19-4e43-bff9-a30d4ac8deb4" />

copy the scan Id from the results
<img width="1024" height="802" alt="image" src="https://github.com/user-attachments/assets/e3a74db5-4ff8-4f9a-9651-ce58f2a386fb" />

go to score_findings endpoint and enter the scan Id and the context overrides listed in the examples folder
<img width="1486" height="927" alt="image" src="https://github.com/user-attachments/assets/dba58f31-5b5a-492f-a79f-b1e2481ca604" />

You must get the priority listed as below
<img width="1493" height="915" alt="image" src="https://github.com/user-attachments/assets/4ff5104b-5951-498e-a2b8-d39030f2f519" />
