import os
import json
from collections import defaultdict

def combine_json_files():
    # Get current working directory
    workdir = os.getcwd()
    
    # Dictionary to store combined data by tool name
    combined_data = defaultdict(list)
    
    # Dictionary to track the highest measurement number for each tool
    max_measurement = defaultdict(int)
    
    # Walk through all directories in the working directory
    for root, dirs, files in os.walk(workdir):
        # Skip the current directory itself
        if root == workdir:
            continue
            
        # Process each JSON file in the directory
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        
                        # If data is a single object, convert to list
                        if isinstance(data, dict):
                            data = [data]
                            
                        # Process each measurement
                        for measurement in data:
                            tool_name = measurement.get('toolName')
                            if tool_name:
                                # Update max measurement number
                                current_measurement = measurement.get('measurementNumber', 0)
                                max_measurement[tool_name] = max(max_measurement[tool_name], current_measurement)
                                combined_data[tool_name].append(measurement)
                                
                except json.JSONDecodeError:
                    print(f"Error decoding JSON file: {file_path}")
                except Exception as e:
                    print(f"Error processing file {file_path}: {str(e)}")
    
    # Create output directory if it doesn't exist
    output_dir = os.path.join(workdir, 'combined_output')
    os.makedirs(output_dir, exist_ok=True)
    
    # Process and save combined data for each tool
    for tool_name, measurements in combined_data.items():
        # Sort measurements by measurement number
        measurements.sort(key=lambda x: x.get('measurementNumber', 0))
        
        # Renumber measurements sequentially
        current_max = max_measurement[tool_name]
        for i, measurement in enumerate(measurements, 1):
            measurement['measurementNumber'] = i
            
        # Save combined JSON
        output_file = os.path.join(output_dir, f'{tool_name}_combined.json')
        try:
            with open(output_file, 'w') as f:
                json.dump(measurements, f, indent=2)
            print(f"Successfully created combined JSON for {tool_name}: {output_file}")
        except Exception as e:
            print(f"Error writing combined JSON for {tool_name}: {str(e)}")
            
        # If there are more measurements to be added later, they should start from
        # the next number after the current maximum
        max_measurement[tool_name] = len(measurements)

if __name__ == '__main__':
    combine_json_files()
