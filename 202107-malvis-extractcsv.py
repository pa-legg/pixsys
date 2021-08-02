#!/usr/bin/env python

# Investigating malware propagation and behaviour using system and network visualisation techniques

import json
import datetime
import sys
import os
import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
import numpy as np
from PIL import Image
import PIL

vboxmetrics_data = []
psutil_data = []
pcap_data = []
net_data = []
screen_data = []

input_name = '20210705_wannacry'
#input_name = '20210722_notpetya'

input_directory = './data/' + input_name
output_screenshot_stack_file_name = input_name + '.png'
output_directory = './results_' + input_name

if not (os.path.isdir(output_directory)):
	os.mkdir(output_directory)

start_minute = -1
end_minute = 60


vbox_metric_counter = 0

color_9pt = ['#e41a1c','#377eb8','#4daf4a','#984ea3','#ff7f00','#ffff33','#a65628','#f781bf','#999999']

color_9ptpy = [[228,26,28],[55,126,184],[77,175,74],[152,78,163],[255,127,0],[255,255,51],[166,86,40],[247,129,191],[153,153,153]]

#https://sashamaps.net/docs/resources/20-colors/
color_9ptpy = [[230,25,75], [60,180,75], [255,225,25], [67,99,216], [245,130,49], [145,30,180], [66,212,244], [240,50,230], [191,239,69], [250,190,212], [70,153,144], [220,190,255],[154,99,36], [255,250,200], [128,0,0], [170,255,195]]
color_js = ['#e6194B', '#3cb44b', '#ffe119', '#4363d8', '#f58231', '#911eb4', '#42d4f4', '#f032e6', '#bfef45', '#fabed4', '#469990', '#dcbeff', '#9A6324', '#fffac8', '#800000', '#aaffc3', '#808000', '#ffd8b1', '#000075', '#a9a9a9', '#ffffff', '#000000']


dir_listing = sorted(os.listdir(input_directory))
for d in dir_listing:
	if 'data' in d:
		if len(vboxmetrics_data) == 0:
			vboxmetrics_data.append(d)
			vbox_metric_counter = vbox_metric_counter + 1
		else:
			parts = vboxmetrics_data[len(vboxmetrics_data)-1].split('-')
			new_parts = d.split('-')
			if parts[3] == new_parts[3] and parts[4] == new_parts[4]:
				
				if vbox_metric_counter == 4:
					pass
				else:
					vboxmetrics_data.append(d)
					vbox_metric_counter = vbox_metric_counter + 1
			else:
				vbox_metric_counter = 0
				vboxmetrics_data.append(d)
				vbox_metric_counter = vbox_metric_counter + 1
	elif 'pcap' in d:
		pcap_data.append(d)
	elif 'png' in d:
		screen_data.append(d)
	elif 'json' in d:
		psutil_data.append(d)
	elif 'csv' in d:
		net_data.append(d)

def load_network_csv_data():
	data = pd.read_csv(input_directory + '/' + net_data[0])
	grouped_data = []
	last_seconds = -1
	minimum = 50
	entries = []
	
	for d in range(len(data)):
		row = data.iloc[d]
		#print ("dt entry", row)
		minutes = int(float(row['Time'].split(":")[1]))
		seconds = int(float(row['Time'].split(":")[2]))
		#print (int(float(seconds)), " --- ", last_seconds)
		if d==0:
			print ("First row: ", row)
		if d==len(data)-1:
			print ("Last row: ", row)

		if (minutes >= start_minute) and (minutes <= end_minute):
			if (seconds >= 0 and seconds < 15 and last_seconds >= 45 and last_seconds < 60):
				#print ("THIS-1")
				grouped_data.append(pd.DataFrame(entries))
				entries = []
			elif (seconds >= 15 and seconds < 30 and last_seconds >= 0 and last_seconds < 15):
				#print ("THIS-2")
				grouped_data.append(pd.DataFrame(entries))
				entries = []
			elif (seconds >= 30 and seconds < 45 and last_seconds >= 15 and last_seconds < 30):
				#print ("THIS-3")
				grouped_data.append(pd.DataFrame(entries))
				entries = []
			elif (seconds >= 45 and seconds < 60 and last_seconds >= 30 and last_seconds < 45):
				#print ("THIS-4")
				grouped_data.append(pd.DataFrame(entries))
				entries = []

		entries.append(row)
		last_seconds = seconds

	return data, grouped_data

def create_csv_data(d, filename, datatype):

	if (show_diagnostic_print):
		print ("D SHAPE", d.shape)

	filename = output_directory + '/' + filename

	if datatype == 'cpu' or datatype == 'ram':
		df = pd.DataFrame(d)
		df.to_csv(filename + ".csv")
	elif datatype == 'net':
		df = pd.DataFrame(d)
		df.to_csv(filename + "_0.csv")
	elif datatype == 'proc':
		df = pd.DataFrame(d)
		df.to_csv(filename + ".csv")

def perform_data_extraction():
	print ("Start data extraction...")
	output = {}

	offset = 10

	img2 = np.ones([100, 100, 3]) * 255

	final_image = []

	#PLOTTING OF METRICS - CPU AND RAM USAGE
	if (plot_cpu_ram_usage):
		print ("Parsing CPU and RAM usage...")

		cpu = {}
		ram = {}
		rx = {}
		tx = {}

		for i in range(len(vboxmetrics_data)):
			example = vboxmetrics_data[i]
			if i==0:
				print ("First file: ", example)
			if i==len(vboxmetrics_data)-1:
				print ("Last file: ", example)
			#print (example)
			with open(input_directory + "/" + example, "r") as fd:
				data = fd.read()
			data = ' '.join(data.split())
			data = data.split('\\n')
			for d in data:
				d= d.split(' ')
				d_len = len(d)
				
				if d_len == 3:
					
					if d[1] == 'CPU/Load/Kernel':
						#print (d, d_len)
						if d[0] not in cpu:
							cpu[d[0]] = []
						cpu[d[0]].append(float(d[2][:-1]))
						
				if d_len == 4:
					
					if d[1] == 'CPU/Load/Kernel':
						if d[0] not in cpu:
							cpu[d[0]] = []
						cpu[d[0]].append(float(d[2][:-1]))
						
					if d[1] == 'RAM/Usage/Used':
						if d[0] not in ram:
							ram[d[0]] = []
						ram[d[0]].append(float(d[2]))
						
					if d[1] == 'Net/Rate/Rx':
						if d[0] not in rx:
							rx[d[0]] = []
						rx[d[0]].append(float(d[2]))
						
					if d[1] == 'Net/Rate/Tx':
						if d[0] not in tx:
							tx[d[0]] = []
						tx[d[0]].append(float(d[2]))

		if (show_diagnostic_print):
			print ("cpu.keys()", cpu.keys())
		rows = []
		for k in cpu.keys():
			#if k != 'host':
			if 'Win7' in k:
				row = cpu[k] / np.max(cpu[k])
				#rows.append(row[0:68])
				rows.append(row)

				
		img_cpu = np.array(rows)
		img_cpu_cols = np.array(['Win7_64bit_node_1', 'Win7_64bit_node_2', 'Win7_64bit_node_3', 'Win7_64bit_node_4'])
		if (show_diagnostic_print):
			print (img_cpu_cols)
		img_cpu_cols = np.reshape(img_cpu_cols, (4,1))
		img_cpu = np.hstack([img_cpu_cols, img_cpu])

		#print ("ram.keys()", ram.keys())
		rows = []
		for k in ram.keys():
			#if k != 'host' and k !='Ubuntu':
			if 'Win7' in k:
				row = ram[k] / np.max(ram[k])
				#rows.append(row[0:68])
				rows.append(row)
				
				
		img_ram = np.array(rows)
		img_ram_cols = np.array(['Win7_64bit_node_1', 'Win7_64bit_node_2', 'Win7_64bit_node_3', 'Win7_64bit_node_4'])
		img_ram_cols = np.reshape(img_ram_cols, (4,1))
		img_ram = np.hstack([img_ram_cols, img_ram])
		
		img_cpu= np.stack(img_cpu)
		img_ram= np.stack(img_ram)
		
		create_csv_data(img_cpu, 'cpu', 'cpu')
		create_csv_data(img_ram, 'ram', 'ram')



	# PLOTTING OF SCREEN CAPTURES
	if (plot_screen_captures):
		print ("Parsing screen captures...")

		#output_file_name = './results/screen_capture.png'
		#image_stack = create_image_stack(input_directory, output_file_name)
		#final_image = np.vstack[[final_image, image_stack]]

		print ("Skip during data extract phase...")

	# PLOTTING OF NETWORK ACTIVITY AND PROTOCOLS
	if (plot_net_activity):
		print ("Parsing network activity...")
		data, grouped_data = load_network_csv_data()

		src_addresses = sorted(data['Source'].unique().tolist())[1:5]
		dst_addresses = sorted(data['Destination'].unique().tolist())[1:5] # start from 1 to remove 10.10.5.10
		protos = sorted(data['Protocol'].unique())

		if (show_diagnostic_print):
			print (src_addresses)
			print (dst_addresses)
			print (protos)

		output['protocols_shown'] = protos



		pnts = []

		color_set = color_9ptpy

		ppp = []

		new_net_matrix1 = np.zeros([(len(src_addresses) * (len(protos))), len(grouped_data)])
		new_net_matrix2 = np.ones([(len(src_addresses) * (len(protos))), len(grouped_data)]) * -1

		col1 = []
		for i in range(len(src_addresses)):
			for j in range(len(protos)):
				col1.append(src_addresses[i])

		col2 = []
		for i in range(len(src_addresses)):
			col2.append(protos)

		col1 = np.array(col1)
		col1 = col1.reshape([len(src_addresses) * len(protos), 1])

		col2 = np.array(col2)
		col2 = col2.reshape([len(src_addresses) * len(protos), 1])


		new_net_matrix1 = np.hstack([col2,  new_net_matrix1]) 
		new_net_matrix1 = np.hstack([col1,  new_net_matrix1]) 
		new_net_matrix2 = np.hstack([col2,  new_net_matrix2]) 
		new_net_matrix2 = np.hstack([col1,  new_net_matrix2]) 

		if (show_diagnostic_print):
			print(new_net_matrix1)
			print(new_net_matrix1.shape)

		for g in range(len(grouped_data)):
			row_counter = 0

			for s in range(len(src_addresses)):
				this_src = src_addresses[s]
				if (show_diagnostic_print):
					print (this_src)
				ggg = grouped_data[g][ grouped_data[g]['Source'] == this_src ]

				#print("Activity ", g, this_src, "Count:", len(ggg))
				#if 'Destination' in ggg:
				#	print ("--- ", "Dest Count:", len(ggg['Destination'].unique()))
					
				for p123 in range(len(protos)):
					this_prot = protos[p123]
					ttt = ggg[ ggg['Protocol'] == this_prot ]
					spdst = ttt['Destination'].unique()

					max_spdst = -1
					index_spdst = -1

					#if len(ttt) > 0:
						#print("Activity ", g, "Source:", this_src, "Protocol:", this_prot, "Dest count:", spdst, len(spdst))

					if len(spdst) > 1:
						for ssssww in range(len(spdst)):
							if str(ttt['Destination']) in dst_addresses:
								count_srcdst = len(ttt[ttt['Destination'] == spdst[ssssww]])
								if count_srcdst > max_spdst:
									index_spdst = dst_addresses.index(spdst[ssssww]) 
									max_spdst = count_srcdst
								#print ("--- --- Count of", this_src, " to ", spdst[ssssww], "with protocol", this_prot, " = ", count_srcdst)
					else:
						if len(spdst) > 0:
							if spdst[0] in dst_addresses:
								index_spdst = dst_addresses.index(spdst[0]) 



					value = len(ttt)
					m = 1

					if (index_spdst) != -1:
						#print ("Value:", value, "index_spdst:", index_spdst)
						new_net_matrix1[row_counter, 2+g] = value
						new_net_matrix2[row_counter, 2+g] = index_spdst
					row_counter = row_counter + 1


		create_csv_data(new_net_matrix1, 'net1', 'net')
		create_csv_data(new_net_matrix2, 'net2', 'net')


	# PLOTTING OF SYSTEM PROCESSES
	if (plot_sys_processes):
		json_data = []
		print ("Parsing system processes...")
		for iiii in range(len(psutil_data)):
			file_name = input_directory + "/" + psutil_data[iiii]
			if (show_diagnostic_print):
				print (file_name)
			f = open(file_name, "r")
			
			for i in range(10000):
				try:
					d = f.readline(-1)
					d_all = d.split('/')
					dt = d_all[0]
					d = d_all[1]
					#print (d)
					if len(d) > 2:
						d = json.loads(d)
						#print (i, dt, d)
						d['dt_now'] = dt
						#print (i, dt, d)
						json_data.append(d)
						#input ("Press Enter to continue...")
					#print ("Row length: ", len(d), d)
				except:
					pass
					#print ("Some error: " , i, "JSON len: ", len(json_data))

		#print ("Plotting system processes...")
		#for iiii in range(len(psutil_data)):

		process_names = []
		process_by_machine = {}
		process_by_machine_and_time = {}

		for i in range(len(json_data)):
			ddd = json_data[i]
			if i==0:
				print ("First data:", ddd)
			if i==len(json_data)-1:
				print ("Last data:", ddd)
			if (show_diagnostic_print):
				print (i, ddd['dt_now'], ddd['machine']) # now we can see time by machine
			if ddd['machine'] not in process_by_machine:
				process_by_machine[ddd['machine']] = []
			process_by_machine[ddd['machine']].append([ddd['dt_now'], ddd['processes_info']])
			for j in range(len(ddd['processes_info'])):
				if ddd['processes_info'][j]['name'] not in process_names:
					process_names.append(ddd['processes_info'][j]['name'])

		process_names = sorted(process_names)
		if (show_diagnostic_print):
			print ("UNIQUE PROC: ", process_names, len(process_names))
			print ("PROC BY MACHINE", process_by_machine.keys())

		


		
		for k in process_by_machine.keys():
			#print("THIS:", k, len(process_by_machine[k]))
			row_machine_process = []

			process_by_machine_and_time[k] = []
			entries = []
			last_seconds = -1
			if (show_diagnostic_print):
				print ("START")
			for kk in range(len(process_by_machine[k])):
				#print (process_by_machine[k][kk])
				#print (process_by_machine[k][kk][0])
				dt = process_by_machine[k][kk][0]
				#print ("-- ", process_by_machine[k][kk][1])
				minutes = int(float(dt.split(":")[1]))
				seconds = int(float(dt.split(":")[2]))
				#print (minutes, seconds, last_seconds)
				#if (minutes >= 20) and (minutes <= 30):
				if (minutes >= start_minute) and (minutes <= end_minute):
					if (seconds >= 0 and seconds < 15 and last_seconds >= 45 and last_seconds < 60):
						#print ("THIS-PROC-1", dt, "entries: ", len(entries))
						#for e in entries:
							#print (" - " + str(e))
						process_by_machine_and_time[k].append(entries)
						entries = []
					elif (seconds >= 15 and seconds < 30 and last_seconds >= 0 and last_seconds < 15):
						#print ("THIS-PROC-2", dt, "entries: ", len(entries))
						#for e in entries:
							#print (" - " + str(e))
						process_by_machine_and_time[k].append(entries)
						entries = []
					elif (seconds >= 30 and seconds < 45 and last_seconds >= 15 and last_seconds < 30):
						#print ("THIS-PROC-3", dt, "entries: ", len(entries))
						#for e in entries:
							#print (" - " + str(e))
						process_by_machine_and_time[k].append(entries)
						entries = []
					elif (seconds >= 45 and seconds < 60 and last_seconds >= 30 and last_seconds < 45):
						#print ("THIS-PROC-4", dt, "entries: ", len(entries))
						#for e in entries:
							#print (" - " + str(e))
						process_by_machine_and_time[k].append(entries)
						entries = []
				#print (process_by_machine[k][kk][1])
				entries.append(process_by_machine[k][kk])
				last_seconds = seconds
			if (show_diagnostic_print):
				print ("END")
				print ("k:", k, "Entries: ", entries)

		


		proc_mat = {}
			
		for k in process_by_machine_and_time.keys():
			if (show_diagnostic_print):
				print (k)
			proc_count_per_period = [k] * len(process_names)
			proc_mat[k] = []
			proc_mat[k].append(proc_count_per_period)
			proc_mat[k].append(process_names)

			
			my_list_of_keys = list(process_by_machine_and_time.keys())

			row_colour = my_list_of_keys.index(k)
			pixel_size = 2


			proc_matrix = np.ones([(len(process_names)*5)+50, offset + (len(process_by_machine_and_time.keys()) * 5)+50 , 3]) * 255

			#print ("Len:", len(process_by_machine_and_time[k]))
			for kk in range(len(process_by_machine_and_time[k])):
				if (show_diagnostic_print):
					print (iiii, "--", k, "-", kk, " -- ")
				proc_count_per_period = [0] * len(process_names)
				for kkk in range(len(process_by_machine_and_time[k][kk])):
					#print ("  ", kkk, " ---   ", process_by_machine_and_time[k][kk][kkk])
					if (show_diagnostic_print):
						print (" dt ", process_by_machine_and_time[k][kk][kkk][0])
					for nn in range(len(process_by_machine_and_time[k][kk][kkk][1])):
						#print (process_by_machine_and_time[k][kk][kkk][1][nn]['name'])
						index = process_names.index(process_by_machine_and_time[k][kk][kkk][1][nn]['name'])  
						proc_count_per_period[index] = proc_count_per_period[index] + 1
				

				if (show_diagnostic_print):
					print (proc_count_per_period, len(proc_count_per_period))
				proc_mat[k].append(proc_count_per_period)


			proc_mat[k] = np.array(proc_mat[k])
			proc_mat[k] = np.transpose(proc_mat[k])
			if (show_diagnostic_print):
				print (proc_mat[k], proc_mat[k].shape)
			create_csv_data(proc_mat[k], 'proc'+k, 'proc')



	print ("All done...")
	return json.dumps(output)

def render_csv_data():
	# split out the data extraction and the vis rendering process
	pass

	print ("Saving image for ", k)
	plt.imsave('./proc_' + str(k) + '.png', proc_matrix.astype(np.uint8))

	from PIL import Image, ImageDraw, ImageFont

	img = Image.open('./proc_' + str(k) + '.png')
	for pn in range(len(process_names)):
		d1 = ImageDraw.Draw(img)
		myFont = ImageFont.truetype("Helvetica.ttf", 8)
		d1.text((0, (pn*9)), process_names[pn], font=myFont, fill = (255, 0, 0))
	#img.show()
	img.save('./proc_' + str(k) + '_withtext.png')

####################################################

plot_cpu_ram_usage = False
plot_screen_captures = False
plot_net_activity = False
plot_sys_processes = False
show_diagnostic_print = False

if len(sys.argv) > 1:
	if sys.argv[1] == '-all':
		plot_cpu_ram_usage = True
		plot_screen_captures = True
		plot_net_activity = True
		plot_sys_processes = True
	for i in range(len(sys.argv)):
		if sys.argv[i] == '-cpu':
			plot_cpu_ram_usage = True
		if sys.argv[i] == '-screen':
			plot_screen_captures = True
		if sys.argv[i] == '-net':
			plot_net_activity = True
		if sys.argv[i] == '-proc':
			plot_sys_processes = True
		if sys.argv[i] == '-v':
			show_diagnostic_print = True
else:
	print ("No parameters given....")
	sys.exit(0)


print ("Investigating malware propagation and behaviour using system and network visualisation techniques")

print (" -Options: cpu-ram:", plot_cpu_ram_usage)
print (" -Options: screen: ", plot_screen_captures)
print (" -Options: net: ", plot_net_activity)
print (" -Options: proc: ", plot_sys_processes)

perform_data_extraction()

#render_csv_data()



