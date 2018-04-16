package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.*;
import java.util.*;

/**
 * Golden Ticket detection using Windows Event log.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class GoldenTicketDetector {

	// キーはアカウント名、値はEventLogDataオブジェクトのリスト。アカウント毎に分類するため
	private static Map<String, LinkedHashSet<EventLogData>> log;
	private static String outputDirName = null;

	// Initial value for timeCnt
	private static short TIME_CNT = Short.MAX_VALUE;

	// Command execution rate for alert
	private static double ALERT_SEVIRE = 0.85;
	private static double ALERT_WARNING = 0.2;

	private static int EVENT_PROCESS = 4688;
	private static int EVENT_PRIV = 4672;
	private static int EVENT_TGT = 4768;
	private static int EVENT_ST = 4769;
	private static int EVENT_SHARE = 5140;

	// Alert Level
	protected enum Alert {
		SEVERE, WARNING, NOTICE, NONE
	}

	// Alert type
	protected enum AlertType {
		NoTGT, MALCMD, ADMINSHARE, PSEXEC,NoADMIN, NoSystemCMD,NONE
	}

	// Alert type and message
	private Map<AlertType, String> alert = null;
	
	// admin account white list
	private List<String> adminWhiteList = null;

	// Suspicious command list
	private List<String> suspiciousCmd = null;

	// account name for detection
	private Set<String> accounts = new LinkedHashSet<String>();
	
	// account name for detection(Domain Admin Privilege accounts)
	private Set<String> adminAccounts = new LinkedHashSet<String>();

	private int detecctTargetcmdCnt = 0;

	private FileWriter filewriter = null;
	private BufferedWriter bw = null;
	private PrintWriter pw = null;

	// Data format
	private static SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");

	private int logCnt = 0;
	private int detectedEventNum = 0;
	private int dataNum=0;
	private int infectedNum=0;

	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int eventID = -1;
			String date = "";
			LinkedHashSet<EventLogData> evSet = null;
			String accountName = "";
			String clientAddress = "";
			String serviceName = "";
			String processName = "";
			String shredName = "";
			String objectName = "";
			boolean isTargetEvent = false;

			// splitする際の上限回数
			int limit = 0;

			// categorize same operations based on time stamp
			short timeCnt = TIME_CNT;
			Date baseDate = null;
			Date logDate = null;

			while ((line = br.readLine()) != null) {
				int clientPort = 0;
				// Remove tab
				line = line.replaceAll("\\t", "");
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (line.contains("Microsoft-Windows-Security-Auditing,")) {
						date = data[1];
						eventID = Integer.parseInt(data[3]);
						if (line.contains(String.valueOf(EVENT_TGT)) || line.contains(String.valueOf(EVENT_ST))
								|| line.contains(String.valueOf(EVENT_PRIV))
								|| line.contains(String.valueOf(EVENT_PROCESS))
								|| line.contains(String.valueOf(EVENT_SHARE))) {
							isTargetEvent = true;
							
							try {
								// Get date
								logDate = sdf.parse(date);
								if (EVENT_ST == eventID && null == baseDate) {
									// this.EVENT_ST を起点として同じ時間帯に出ているログを調べる
									baseDate = sdf.parse(date);
									timeCnt--;
								} else if (null != baseDate) {
									// ログのタイムスタンプ差を調べる
									long logTime = logDate.getTime();
									long baseTime = baseDate.getTime();
									long timeDiff = (baseTime - logTime) / 1000;
									if (timeDiff > 1) {
										// 1秒以上離れているログには異なるtimeCntを割り当てる
										timeCnt--;
										baseDate = sdf.parse(date);
									}
								}

							} catch (ParseException e) {
								e.printStackTrace();
							}
						} else {
							isTargetEvent = false;
						}
					} else if (isTargetEvent) {
						if (elem.contains("アカウント名:") || elem.contains("Account Name:")) {
							accountName = parseElement(elem, ":", limit);
							if (accountName.isEmpty()) {
								continue;
							} else {
								// ドメイン名は取り除き、全て小文字にする
								accountName = accountName.split("@")[0].toLowerCase();
								if (null == log.get(accountName)) {
									evSet = new LinkedHashSet<EventLogData>();
								} else {
									evSet = log.get(accountName);
								}
									if (EVENT_PRIV == eventID) {
										// 4672はこれ以上情報がないので、アカウント名だけ取得し、管理者アカウントリストに入れる
										accounts.add(accountName);
										adminAccounts.add(accountName);
										evSet.add(new EventLogData(date, "", accountName, eventID, 0,
												"", "", timeCnt));
										log.put(accountName, evSet);
										continue;
									}else {
									// extract all users
									accounts.add(accountName);
								}
							}

						} else if (elem.contains("サービス名:") || elem.contains("Service Name:")) {
							serviceName = parseElement(elem, ":", limit);
						} else if (elem.contains("クライアント アドレス:") || elem.contains("Client Address:")
								|| elem.contains("ソース ネットワーク アドレス:") || elem.contains("Source Network Address:")
								|| elem.contains("送信元アドレス:")|| elem.contains("Source Address:")) {
							elem = elem.replaceAll("::ffff:", "");
							clientAddress = parseElement(elem, ":", limit);

						} else if ((elem.contains("クライアント ポート:") || elem.contains("Client Port:")
								|| elem.contains("ソース ポート:"))|| elem.contains("Source Port:")) {
							try {
								clientPort = Integer.parseInt(parseElement(elem, ":", limit));
							} catch (NumberFormatException e) {
								// nothing
							}
							evSet.add(new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt));
							if (EVENT_SHARE != eventID) {
								// 5140は共有名の情報を取得してから格納する
								log.put(accountName, evSet);
							}
						} else if (elem.contains("オブジェクト名:")|| elem.contains("Object Name:")) {
							objectName = parseElement(elem, ":", 2).toLowerCase();
						} else if ((elem.contains("プロセス名:") || elem.contains("Process Name:"))) {
							// プロセス名は":"が含まれることがあることを考慮
							processName = parseElement(elem, ":", 2).toLowerCase();
							
							// 認証要求元は記録されない
							clientAddress = "";
							EventLogData ev = new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt);
							ev.setObjectName(objectName);
							evSet.add(ev);
							log.put(accountName, evSet);
							processName = "";
							objectName = "";
						} else if (elem.contains("共有名:")||elem.contains("Share Name:")) {
							EventLogData ev = new EventLogData(date, clientAddress, accountName, eventID, clientPort,
									serviceName, processName, timeCnt);
							shredName = parseElement(elem, ":", 2).toLowerCase();
							ev.setSharedName(shredName);
							evSet.add(ev);
							log.put(accountName, evSet);
							shredName = "";
						}
					}
				}
			}
			br.close();
		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter, int limit) {
		String value = "";
		try {
			String elems[] = elem.trim().split(delimiter, limit);
			if (elems.length >= 2) {
				value = elems[1];
				value = value.replaceAll("\t", "");
			}
		} catch (RuntimeException e) {
			System.out.println(elem);
			e.printStackTrace();
		}
		if (value.isEmpty()) {
			value = "";
		}
		return value;
	}

	private void outputResults(Map map, String outputFileName) {
		try {
			// normal result
			filewriter = new FileWriter(outputFileName, true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			pw.println("date,eventID,account,ip,service,process,sharedname,target,alerttype,alertlevel");
			
			System.out.println("Infected accounts and computers:");

			ArrayList<EventLogData> list = null;

			// アカウントごとに処理する
			for (String accountName : accounts) {
				LinkedHashSet<EventLogData> evS = log.get(accountName);
				if (null == evS) {
					continue;
				}
				// ソース IPが出ないイベントに、ソースIPをセットする
				setClientAddress(evS);

				// クライアントアドレス毎にログを保持するためのリスト(キー：クライアントアドレス)
				Map<String, LinkedHashSet> kerlog = new LinkedHashMap<String, LinkedHashSet>();

				// 同じ時間帯毎にログを保持するためのリスト(キー：クライアントアドレス)
				Map<Long, LinkedHashSet> timeBasedlog = new LinkedHashMap<Long, LinkedHashSet>();

				// さらにクライアントアドレスごとに分類し、GTが使われている可能性があるかを判定する
				for (EventLogData ev : evS) {
					LinkedHashSet<EventLogData> evSet;
					String clientAddress=ev.getClientAddress();
					if (null != kerlog.get(clientAddress)) {
						evSet = kerlog.get(clientAddress);
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					kerlog.put(ev.getClientAddress(), evSet);
					this.logCnt++;
				}
				
				for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
						Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
						String computer=entry.getKey();
						if(!accountName.isEmpty() && !computer.isEmpty()) {
							this.dataNum++;
							//System.out.println("Account: "+accountName+", Computer: "+computer);
						}
				}
				// GTが使われているか判定
				if(adminAccounts.contains(accountName)){
					isGoldenUsed(kerlog,accountName);
				}
				// 同じ時間帯のログごとに処理
				list = new ArrayList<EventLogData>(evS);
				Collections.reverse(list);
				for (EventLogData ev : list) {
					LinkedHashSet<EventLogData> evSet;
					if (null != timeBasedlog.get(ev.getTimeCnt())) {
						evSet = timeBasedlog.get(ev.getTimeCnt());
					} else {
						evSet = new LinkedHashSet<EventLogData>();
					}
					evSet.add(ev);
					timeBasedlog.put(ev.getTimeCnt(), evSet);
				}
				// 結果をファイルに出力する
				outputLogs(timeBasedlog, accountName);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void isGoldenUsed(Map<String, LinkedHashSet> kerlog, String accountName) {
		// kerlogは端末毎に分類されたログ
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			boolean isTGTEvent = false;
			boolean isSTEvent = false;
			short isGolden = 0;
			Map.Entry<String, LinkedHashSet> entry = (Map.Entry<String, LinkedHashSet>) it.next();
			String computer=entry.getKey();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
			LinkedHashSet<Long> attackTimeCnt=new LinkedHashSet<Long>();
			for (EventLogData ev : evS) {
				int eventID = ev.getEventID();
				// 4768/479が記録されているかを調べる
				if (eventID == 4768) {
					isTGTEvent = true;
				} else if (eventID == EVENT_ST) {
					isSTEvent = true;
				}
			}
			if (!isTGTEvent && isSTEvent) {
				// 4768が記録されていないのに、4769が記録されている
				isGolden = 1;
				System.out.println("Account: "+accountName+", Computer: "+computer);
				for (EventLogData ev : evS) {
					if (EVENT_ST == ev.getEventID()) {
						ev.setIsGolden(isGolden);
						ev.setAlertType(AlertType.NoTGT);
						ev.setAlertLevel(Alert.SEVERE);
					}
				}
			}
			Set<String> commands = new LinkedHashSet<String>();
			for (EventLogData ev : evS) {
				if(ev.getEventID()==EVENT_PRIV &&!this.adminWhiteList.contains(accountName) 
						&& this.adminAccounts.contains(accountName)){
					// 管理者リストに含まれていないのに、特権を使っている
					isGolden = 1;
					ev.setIsGolden(isGolden);
					ev.setAlertType(AlertType.NoADMIN);
					ev.setAlertLevel(Alert.SEVERE);
				}
				if (5140 == ev.getEventID()) {
					// 管理共有が使用されている
					if (ev.getSharedName().contains("\\c$")) {
						isGolden = 1;
						ev.setIsGolden(isGolden);
						ev.setAlertType(AlertType.ADMINSHARE);
						ev.setAlertLevel(Alert.SEVERE);
					}
				} else if (EVENT_PROCESS == ev.getEventID()) {
					// 攻撃者がよく実行するコマンドを実行している
					String command[] = ev.getProcessName().split("\\\\");
					String commandName = "";
					if (null != command) {
						commandName = command[command.length - 1];
					}
					for (String cmd : suspiciousCmd) {
						if (commandName.equals(cmd)) {
							isGolden = 1;
							ev.setIsGolden(isGolden);
							ev.setAlertType(AlertType.MALCMD);
							commands.add(ev.getProcessName());
						}
					}
				}
			}
			// 実行された不審なコマンドの種類数
			int detecctcmdCnt = commands.size();
			double commandExecuterate = (double) detecctcmdCnt / this.detecctTargetcmdCnt;
			Alert alertLevel = Alert.NONE;
			if (commandExecuterate > this.ALERT_SEVIRE) {
				alertLevel = Alert.SEVERE;
			} else if (commandExecuterate > this.ALERT_WARNING) {
				alertLevel = Alert.WARNING;
			} else if (commandExecuterate > 0) {
				alertLevel = Alert.NOTICE;
			}
			for (EventLogData ev : evS) {
				if(ev.getAlertType()==AlertType.MALCMD){
					ev.setAlertLevel(alertLevel);
				}
				if(1==ev.isGolden()){
					if(ev.getClientAddress().isEmpty() && ev.getEventID()!=EVENT_PRIV) {
						ev.setIsGolden((short)0);
						ev.setAlertLevel(Alert.NONE);
						ev.setAlertType(AlertType.NONE);
					} else{
						this.detectedEventNum++;
					}
				}
			}
			if(1==isGolden && !accountName.isEmpty() && !computer.isEmpty()){
				infectedNum++;
				System.out.println("Account: "+accountName+", Computer: "+computer);
			}
		}
	}
	
	private void outputLogs(Map<Long, LinkedHashSet> kerlog, String accountName) {
		for (Iterator it = kerlog.entrySet().iterator(); it.hasNext();) {
			Map.Entry<Long, LinkedHashSet> entry = (Map.Entry<Long, LinkedHashSet>) it.next();
			LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();

			long logTime = 0;
			for (EventLogData ev : evS) {
				try {
					logTime = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e1) {
					e1.printStackTrace();
				}

				// UNIX Timeの計算
				long time = 0;
				try {
					time = sdf.parse(ev.getDate()).getTime();
				} catch (ParseException e) {
					e.printStackTrace();
				}
				pw.println(ev.getDate() + "," + ev.getEventID() + "," + accountName + "," + ev.getClientAddress() + ","
						+ ev.getServiceName() + "," + ev.getProcessName() + "," 
						+ ev.getSharedName() + "," + ev.isGolden() + "," + this.alert.get(ev.getAlertType()) + ","
						+ ev.getAlertLevel());
			}
		}

	}

	/**
	 * Parse CSV files exported from event log. Detect possibility of attacks
	 * using Golden Ticket
	 * 
	 * @param inputDirname
	 */
	public void detectGolden(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
			} else {
				continue;
			}
		}
		outputResults(log, this.outputDirName + "/" + "result.csv");
	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println(
				"{iputdirpath} {outputdirpath} {suspicious command list file} ({admin list})");
	}

	/**
	 * Read suspicious command list
	 * 
	 * @param inputfilename
	 */
	private void readSuspiciousCmd(String inputfilename) {

		File f = new File(inputfilename);
		suspiciousCmd = new ArrayList<String>();
		try {
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				suspiciousCmd.add(line);
			}
			this.detecctTargetcmdCnt = this.suspiciousCmd.size();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Read admin list
	 * @param inputfilename
	 */
	private void readAdminList(String inputfilename) {

		File f = new File(inputfilename);
		adminWhiteList = new ArrayList<String>();
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				adminWhiteList.add(line);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void setAlert() {
		this.alert = new HashMap<AlertType, String>();
		alert.put(AlertType.NoTGT, "No TGT request");
		alert.put(AlertType.MALCMD, "Malicious Command");
		alert.put(AlertType.ADMINSHARE, "Administrative Share");
		alert.put(AlertType.PSEXEC, "Psexec used");
		alert.put(AlertType.NoSystemCMD, "Non system command uses sensitive privilege");
		alert.put(AlertType.NoADMIN, "Not in Admin list");
	}

	private void setClientAddress(LinkedHashSet<EventLogData> evS) {
		List<EventLogData> list = new ArrayList<EventLogData>(evS);
		// 時刻の昇順に並べる
		Collections.reverse(list);
		String clientAddress = "";
		for (EventLogData ev : list) {
			if (ev.getEventID() == EVENT_ST) {
				clientAddress = ev.getClientAddress();
			} else if (ev.getEventID() == EVENT_PROCESS) {
				if(!clientAddress.isEmpty()){
					ev.setClientAddress(clientAddress);
				}
			}
		}
	}

	private void outputDetectionRate() {
		System.out.println();
		System.out.println("Total amount of events: " + this.logCnt);
		System.out.println("Total amount of accounts & computers: " + this.dataNum);
		System.out.println("TP(event): " + this.detectedEventNum);
		System.out.println("TN(event): " + (this.logCnt - this.detectedEventNum));
		System.out.println("TP(accounts & computers): " + this.infectedNum);
		System.out.println("TN(accounts & computers): " + (this.dataNum - this.infectedNum));
	}

	public static void main(String args[]) throws ParseException {
		GoldenTicketDetector GoldenTicketDetector = new GoldenTicketDetector();
		String inputdirname = "";
		String commandFile = "";
		String adminlist = "";
		if (args.length < 3) {
			printUseage();
		} else
			inputdirname = args[0];
		outputDirName = args[1];
		commandFile = args[2];
		if (args.length > 3) {
			adminlist=args[3];
		}
		log = new LinkedHashMap<String, LinkedHashSet<EventLogData>>();
		GoldenTicketDetector.setAlert();
		GoldenTicketDetector.readSuspiciousCmd(commandFile);
		GoldenTicketDetector.readAdminList(adminlist);
		GoldenTicketDetector.detelePrevFiles(outputDirName);
		GoldenTicketDetector.detectGolden(inputdirname);
		GoldenTicketDetector.outputDetectionRate();
	}

}
