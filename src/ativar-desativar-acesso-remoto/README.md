# desativar-windows-update.ps1

# Configura o Serviço do Windows Update service para "Desativado"
sc.exe config wuauserv start=disabled

# Mostrar o status do serviço
sc.exe query wuauserv

# Para o serviço, no de estar em execução
sc.exe stop wuauserv

# Mostra o status novamente, so para garantir
sc.exe query wuauserv

# verifique se está REALMENTE desativado - o valor inicial deve ser 0x4
REG.exe QUERY HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start 
