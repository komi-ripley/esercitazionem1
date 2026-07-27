# esercitazionem1
Progetti ed esercitazioni Epicode



# Esercizio — Policy di sicurezza di base su Windows


## Obiettivo

Simulare la fase di ricognizione di un attacco da una macchina Kali Linux verso un sistema Windows, bloccare l'attaccante tramite il Firewall di Windows Defender e verificare l'efficacia della difesa analizzando i log nativi del sistema operativo.

## Ambiente

| Ruolo | Sistema | IP |
|---|---|---|
| Attaccante | Kali Linux 2026.2 | 192.168.50.100 |
| Difensore | Windows 11 IoT Enterprise LTSC 2024 | 192.168.50.102 |

Le due macchine virtuali sono collegate tramite rete interna VirtualBox (`intnet`), un segmento isolato senza gateway né accesso a Internet. La rete interna non dispone di DHCP, quindi gli indirizzi IP sono stati assegnati manualmente.

Strumenti: Nmap 7.99 su Kali, Windows Defender Firewall con sicurezza avanzata (`wf.msc`) e PowerShell su Windows.

**Nota sul sistema target.** La traccia prevede Windows 10 metasploitable. Windows 10 ha terminato il supporto il 14 ottobre 2025 e Microsoft ha rimosso dall'Evaluation Center le immagini di valutazione Enterprise. È stato quindi utilizzato Windows 11 IoT Enterprise LTSC, disponibile gratuitamente come valutazione di 90 giorni. Il firewall, il motore delle regole e il file `pfirewall.log` sono identici tra le due versioni, quindi tutti i passaggi della traccia sono stati eseguiti senza modifiche. I servizi da rilevare nella Fase 2 sono stati abilitati manualmente.

## Fase 1 — Verifica della connettività

Assegnazione degli indirizzi statici sul segmento `intnet`.

Kali:

```
sudo ip addr add 192.168.50.100/24 dev eth1
```

Windows (PowerShell come amministratore):

```
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.50.102 -PrefixLength 24
Set-NetConnectionProfile -InterfaceAlias "Ethernet 2" -NetworkCategory Private
```

Test da Kali:

```
ping -c 4 192.168.50.102
```

Output:

```
[INSERIRE OUTPUT PING]
```

![Ping da Kali](screenshots/01-ping.png)

Per impostazione predefinita Windows scarta le richieste ICMP in ingresso: la regola "Condivisione file e stampanti (richiesta echo - ICMPv4-In)" è disabilitata di default. Il ping fallisce quindi anche con la rete perfettamente funzionante. La regola è stata abilitata esplicitamente.

## Fase 2 — Ricognizione con Nmap

Servizi abilitati sul target (PowerShell come amministratore):

```
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"
```

Il firewall è rimasto attivo per l'intera durata dell'esercizio.

Scansione da Kali:

```
nmap -F 192.168.50.102
```

L'opzione `-F` limita la scansione alle 100 porte più comuni anziché alle 1000 predefinite.

Output:

```
[INSERIRE OUTPUT NMAP]
```

![Scansione prima del blocco](screenshots/02-nmap-prima.png)

Porte rilevate: [INSERIRE ELENCO PORTE]

Le porte risultano `open` perché il target risponde con un pacchetto `SYN-ACK` ai sondaggi di Nmap. Per un attaccante questa fase identifica i servizi esposti e quindi i possibili vettori di attacco.

## Fase 3 — Blocco dell'attaccante

Regola creata in `wf.msc` → Regole connessioni in entrata → Nuova regola.

| Parametro | Valore |
|---|---|
| Tipo di regola | Personalizzata |
| Programma | Tutti i programmi |
| Protocollo | Qualsiasi |
| Indirizzi IP remoti | 192.168.50.100 |
| Azione | Blocca la connessione |
| Profili | Dominio, Privato, Pubblico |
| Nome | Blocco_Kali |

![Regola - scheda Ambito](screenshots/03-regola-ambito.png)

![Regola - scheda Azione](screenshots/04-regola-azione.png)

Verifica da Kali:

```
nmap -F -Pn 192.168.50.102
```

Output:

```
[INSERIRE OUTPUT NMAP DOPO IL BLOCCO]
```

![Scansione dopo il blocco](screenshots/05-nmap-dopo.png)

L'opzione `-Pn` si è resa necessaria perché la regola blocca anche i pacchetti di host discovery: senza `-Pn` Nmap segnala "Host seems down" e non esegue alcuna scansione. Il fatto stesso che l'opzione sia richiesta è già una prova dell'efficacia del blocco.

Le porte risultano ora `filtered` e non `closed`:

| Stato | Risposta del target |
|---|---|
| open | SYN-ACK |
| closed | RST |
| filtered | nessuna risposta, pacchetto scartato |

Il firewall scarta i pacchetti senza rispondere, quindi Nmap non può distinguere una porta chiusa da una porta bloccata. Dal punto di vista difensivo è il comportamento preferibile: una risposta `RST` confermerebbe comunque l'esistenza del sistema.



## Conclusioni

| | Prima del blocco | Dopo il blocco |
|---|---|---|
| Rilevamento host | attivo | non rilevabile senza `-Pn` |
| Stato delle porte | open | filtered |
| Informazioni per l'attaccante | servizi identificati | nessuna |
| Tracce sul target | nessuna | righe DROP nel log |

La regola blocca esclusivamente l'indirizzo 192.168.50.100 e non tutto il traffico in entrata, secondo il principio del privilegio minimo: un blocco generico avrebbe reso inutilizzabili anche i servizi legittimi. Nel firewall di Windows le regole di blocco hanno precedenza su quelle di autorizzazione, quindi `Blocco_Kali` prevale sulle regole che consentono SMB e Desktop remoto, ma soltanto per quel singolo indirizzo.

La misura presenta limiti evidenti: un attaccante che cambia indirizzo IP la aggira completamente, le porte restano aperte verso tutte le altre origini e la gestione manuale non è scalabile. Una strategia di difesa reale affianca a questa misura la riduzione dei servizi esposti, la segmentazione di rete e il monitoraggio continuo.

La Fase 4 evidenzia la differenza tra bloccare e rilevare: senza la registrazione, l'attacco sarebbe stato fermato senza lasciare alcuna traccia. I log rendono l'evento analizzabile e costituiscono il presupposto di qualsiasi attività di incident response.

Il firewall nativo di Windows, correttamente configurato, è risultato adeguato a neutralizzare una ricognizione di questo tipo senza ricorrere a software di terze parti.
