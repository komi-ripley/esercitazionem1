# Esercizio: policy di sicurezza di base su Windows

Laboratorio di sicurezza con due macchine virtuali. Da Kali Linux effettuo una scansione delle porte verso un sistema Windows, poi blocco l'attaccante con il firewall nativo e verifico il risultato leggendo i log del sistema.

## Ambiente

| Ruolo | Sistema | IP |
|---|---|---|
| Attaccante | Kali Linux 2026.2 | 192.168.50.100 |
| Difensore | Windows 11 IoT Enterprise LTSC 2024 (build 26100) | 192.168.50.102 |

Entrambe le VM girano su VirtualBox con due schede di rete: la prima in NAT per l'accesso a Internet, la seconda su rete interna `intnet`, che è il segmento su cui si svolge l'esercizio. La rete interna di VirtualBox non ha un server DHCP, quindi gli indirizzi vanno assegnati a mano su tutte e due le macchine.

Strumenti usati: Nmap 7.99 su Kali, `wf.msc` e PowerShell su Windows.

### Nota sul sistema target

La traccia chiede Windows 10 metasploitable. Windows 10 è uscito dal supporto il 14 ottobre 2025 e Microsoft ha tolto dall'Evaluation Center le immagini di valutazione Enterprise, quindi non è più scaricabile per vie ufficiali. Ho usato Windows 11 IoT Enterprise LTSC, disponibile gratuitamente come valutazione di 90 giorni.

La sostituzione non cambia nulla ai fini dell'esercizio: `wf.msc`, il motore delle regole e il file `pfirewall.log` sono identici fra le due versioni. Non essendo un'immagine deliberatamente vulnerabile, i servizi da rilevare nella Fase 2 li ho abilitati io.

## Fase 1. Verifica della connettività

Assegnazione degli indirizzi. Su Kali:

```
sudo ip addr add 192.168.50.100/24 dev eth1
```

Su Windows, da PowerShell come amministratore:

```
New-NetIPAddress -InterfaceAlias "Ethernet 2" -IPAddress 192.168.50.102 -PrefixLength 24
Set-NetConnectionProfile -InterfaceAlias "Ethernet 2" -NetworkCategory Private
```

Il secondo comando serve perché la rete interna viene classificata come "Unidentified network" e finisce nel profilo Pubblico. Forzandola su Privato, le regole del firewall e le impostazioni di logging restano tutte sullo stesso profilo.

Primo tentativo di ping da Kali:

```
$ ping -c 4 192.168.50.102
PING 192.168.50.102 (192.168.50.102) 56(84) bytes of data.

--- 192.168.50.102 ping statistics ---
4 packets transmitted, 0 received, 100% packet loss, time 3210ms
```

Perdita del 100%, ma senza nessun messaggio "Destination Host Unreachable". La differenza conta: i pacchetti arrivavano e venivano scartati in silenzio, quindi il problema era il firewall e non la rete.

Verifica sulla macchina Windows:

```
PS> Get-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" | Select-Object Name, Enabled, Profile

Name    : FPS-ICMP4-ERQ-In
Enabled : False
Profile : Private, Public
```

La regola che gestisce le richieste echo ICMP in ingresso era disabilitata. È il comportamento predefinito di Windows: non risponde al ping finché non lo si autorizza esplicitamente. Da notare che avevo già lanciato `Enable-NetFirewallRule -DisplayGroup "File and Printer Sharing"`, che avrebbe dovuto includerla, e non aveva avuto effetto. Agendo sul nome della singola regola ha funzionato:

```
Set-NetFirewallRule -Name "FPS-ICMP4-ERQ-In" -Enabled True -Profile Any
```

Secondo tentativo:

```
$ ping -c 4 192.168.50.102
PING 192.168.50.102 (192.168.50.102) 56(84) bytes of data.
64 bytes from 192.168.50.102: icmp_seq=1 ttl=128 time=0.783 ms
64 bytes from 192.168.50.102: icmp_seq=2 ttl=128 time=0.544 ms
64 bytes from 192.168.50.102: icmp_seq=3 ttl=128 time=0.826 ms
64 bytes from 192.168.50.102: icmp_seq=4 ttl=128 time=0.618 ms

--- 192.168.50.102 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3036ms
rtt min/avg/max/mdev = 0.544/0.692/0.826/0.115 ms
```

Il `ttl=128` conferma che a rispondere è un host Windows (Linux parte da 64).

## Fase 2. Ricognizione con Nmap

Servizi abilitati sul target prima della scansione:

```
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections" -Value 0
Restart-Service TermService -Force
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

Il firewall è rimasto acceso per tutta la durata dell'esercizio. Lo scenario è quello di un sistema che espone qualche servizio legittimo e che poi deve bloccare un attaccante specifico, non quello di un sistema senza protezioni.

Scansione da Kali, con `-F` che limita il controllo alle 100 porte più comuni invece delle 1000 di default:

```
$ nmap -F 192.168.50.102
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-27 16:40 -0400
Nmap scan report for 192.168.50.102
Host is up (0.00062s latency).
Not shown: 98 filtered tcp ports (no-response)
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server
5357/tcp open  wsdapi
MAC Address: 08:00:27:20:4E:6D (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 6.55 seconds
```

Due porte aperte:

- 3389 (`ms-wbt-server`), il Desktop remoto appena attivato
- 5357 (`wsdapi`), Web Services for Devices, attivo di default sul profilo Privato

Il MAC address risolto come NIC virtuale VirtualBox conferma che sto guardando la macchina giusta e non qualcos'altro sulla rete.

Un dettaglio che non mi aspettavo: controllando sul target con `Get-NetTCPConnection -State Listen` risultavano in ascolto anche 135, 139 e 445, ma da Kali comparivano fra le 98 porte filtrate. Le regole in entrata del gruppo Condivisione file e stampanti erano rimaste disabilitate, esattamente come era successo con la regola ICMP. Il servizio ascolta sul sistema, ma il firewall non lascia passare niente dall'esterno.

Dal punto di vista dell'attaccante questa fase serve a capire quali servizi sono raggiungibili e quindi da dove provare a entrare.

## Fase 3. Blocco dell'attaccante

Regola creata da `wf.msc`, in Regole connessioni in entrata.

| Parametro | Valore |
|---|---|
| Tipo di regola | Personalizzata |
| Programma | Tutti i programmi |
| Protocollo | Qualsiasi |
| Indirizzi IP locali | Qualsiasi |
| Indirizzi IP remoti | 192.168.50.100 |
| Azione | Blocca la connessione |
| Profili | Tutti (Dominio, Privato, Pubblico) |
| Nome | Blocco_Kali |

Il campo importante è quello degli indirizzi remoti. Gli indirizzi locali restano su "Qualsiasi": solo la sorgente viene limitata all'IP di Kali.

Verifica della regola creata, da PowerShell:

```
PS> Get-NetFirewallRule -DisplayName "Blocco_Kali" | Select-Object DisplayName, Enabled, Direction, Action, Profile

DisplayName : Blocco_Kali
Enabled     : True
Direction   : Inbound
Action      : Block
Profile     : Any
```

```
PS> Get-NetFirewallRule -DisplayName "Blocco_Kali" | Get-NetFirewallAddressFilter

LocalAddress  : Any
RemoteAddress : 192.168.50.100
```

(output ridotto ai campi valorizzati)

La regola è attiva, agisce sul traffico in entrata, l'azione è Block e si applica a tutti i profili. Il filtro sugli indirizzi conferma che il vincolo è solo sulla sorgente.

Nuova scansione dopo l'applicazione della regola:

```
$ nmap -F -Pn 192.168.50.102
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-27 16:50 -0400
Nmap scan report for 192.168.50.102
Host is up (0.00055s latency).
All 100 scanned ports on 192.168.50.102 are in ignored states.
Not shown: 100 filtered tcp ports (no-response)
MAC Address: 08:00:27:20:4E:6D (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 7.48 seconds
```

Tutte e 100 le porte filtrate, nessuna aperta. Prima erano due.

L'opzione `-Pn` salta la fase di host discovery. Nmap continua però a riportare `Host is up`, perché le due macchine sono sullo stesso segmento e la risoluzione avviene via ARP, cioè a livello 2, dove il firewall di Windows non interviene. Su una rete instradata, dove il rilevamento passa per ICMP o TCP, il risultato sarebbe stato diverso.

Sul perché le porte risultino `filtered` e non `closed`:

| Stato | Risposta del target |
|---|---|
| open | SYN-ACK |
| closed | RST |
| filtered | nessuna risposta |

Una porta chiusa risponde comunque, con un RST, e quella risposta conferma all'attaccante che il sistema esiste. Il firewall invece scarta il pacchetto senza dire niente, e Nmap non ha modo di distinguere fra una porta chiusa e una bloccata.

## Fase 4. Log del firewall

Configurazione da `wf.msc`, tasto destro su "Windows Defender Firewall con sicurezza avanzata", Proprietà, scheda Profilo privato, sezione Registrazione, Personalizza. Registrazione dei pacchetti ignorati impostata su Sì.

Equivalente da PowerShell, che copre tutti i profili in una riga:

```
Set-NetFirewallProfile -Name Domain,Private,Public -LogBlocked True -LogMaxSizeKilobytes 4096
```

La prima lettura del log non ha prodotto niente. Il file esisteva ma pesava 212 byte, cioè solo l'intestazione: la registrazione era stata attivata dopo la scansione, e il log raccoglie soltanto i pacchetti scartati da quel momento in avanti. Ho rilanciato la scansione da Kali e riletto.

```
PS> Select-String -Path C:\Windows\System32\LogFiles\Firewall\pfirewall.log -Pattern "DROP" | Select-Object -Last 20
```

```
2026-07-27 22:59:56 DROP TCP 192.168.50.100 192.168.50.102 57764 139  44 S 446729687 0 1024 - - - RECEIVE 4
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57766 139  44 S 446860757 0 1024 - - - RECEIVE 4
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57764 445  44 S 446729687 0 1024 - - - RECEIVE 4
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57764 3389 44 S 446729687 0 1024 - - - RECEIVE 8032
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57766 3389 44 S 446860757 0 1024 - - - RECEIVE 8032
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57766 445  44 S 446860757 0 1024 - - - RECEIVE 4
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57764 135  44 S 446729687 0 1024 - - - RECEIVE 588
2026-07-27 22:59:57 DROP TCP 192.168.50.100 192.168.50.102 57766 135  44 S 446860757 0 1024 - - - RECEIVE 588
2026-07-27 22:59:59 DROP TCP 192.168.50.100 192.168.50.102 57764 5357 44 S 446729687 0 1024 - - - RECEIVE 4
2026-07-27 22:59:59 DROP TCP 192.168.50.100 192.168.50.102 57766 5357 44 S 446860757 0 1024 - - - RECEIVE 4
```

Formato dei campi: data, ora, azione, protocollo, IP sorgente, IP destinazione, porta sorgente, porta destinazione, dimensione, flag TCP.

Tutte le righe hanno origine 192.168.50.100 e azione DROP. Il flag `S` indica pacchetti SYN, cioè tentativi di apertura connessione, che è esattamente quello che fa Nmap. Le porte di destinazione sono 139, 445, 3389, 135 e 5357, le stesse che avevo abilitato o che risultavano in ascolto: nel log si vede la scansione che le prova una per una e il firewall che le scarta tutte.

Gli orari del log sono in ora locale di Windows (fuso italiano), mentre Kali era impostato su UTC-4. Le sei ore di differenza spiegano perché una scansione lanciata alle 16:59 su Kali compaia come 22:59 nel log.

## Conclusioni

| | Prima | Dopo |
|---|---|---|
| Porte aperte | 3389, 5357 | nessuna |
| Porte filtrate | 98 | 100 |
| Informazioni ottenute dall'attaccante | due servizi identificati | nessuna |
| Tracce sul target | nessuna | righe DROP nel log |

La regola blocca solo 192.168.50.100, non tutto il traffico in entrata. È una scelta di privilegio minimo: chiudere tutto avrebbe reso il sistema inutilizzabile anche per gli usi legittimi. Nel firewall di Windows le regole di blocco vincono su quelle di autorizzazione, quindi `Blocco_Kali` ha avuto la meglio sulla regola che consentiva il Desktop remoto, ma soltanto per quell'indirizzo. Da qualsiasi altra sorgente la porta 3389 sarebbe rimasta raggiungibile.

I limiti sono evidenti. Un attaccante che cambia indirizzo aggira la regola senza sforzo, e in uno scenario reale gestire a mano una lista di IP malevoli non è praticabile. Il blocco per indirizzo va affiancato ad altro: ridurre i servizi esposti, segmentare la rete, tenere sotto controllo i log.

Su quest'ultimo punto la Fase 4 è la parte più interessante dell'esercizio. Bloccare e accorgersi sono due capacità diverse. Senza registrazione la scansione sarebbe stata fermata comunque, ma nessuno avrebbe saputo che il sistema era stato sondato, da chi e verso quali porte.

Una cosa che porto via dal laboratorio: due volte un comando `Enable-NetFirewallRule -DisplayGroup` non ha prodotto l'effetto atteso senza segnalare errori. Verificare lo stato effettivo delle regole invece di fidarsi dell'esito apparente di un comando ha risolto entrambi i casi.
