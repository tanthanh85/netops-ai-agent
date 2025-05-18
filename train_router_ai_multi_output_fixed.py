
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from datasets import Dataset
from transformers import AutoTokenizer, BertTokenizerFast, BertForSequenceClassification, Trainer, TrainingArguments
import torch
import pickle

# Load new data
df = pd.read_csv("ospf_bgp_cpu_mem_800_cisco_style_reclassified_fixed.csv")

# Prepare encoders
severity_encoder = LabelEncoder()
df["severity_label"] = severity_encoder.fit_transform(["Critical"] * len(df))  # fixed since all are Critical

show_cmd_encoder = LabelEncoder()
df["show_cmd_label"] = show_cmd_encoder.fit_transform(df["show_cmds"])

debug_cmd_encoder = LabelEncoder()
df["debug_cmd_label"] = debug_cmd_encoder.fit_transform(df["debug_cmds"])

# Save encoders
with open("router_ai_model_bert/severity_encoder.pkl", "wb") as f:
    pickle.dump(severity_encoder, f)
with open("router_ai_model_bert/show_cmd_encoder.pkl", "wb") as f:
    pickle.dump(show_cmd_encoder, f)
with open("router_ai_model_bert/debug_cmd_encoder.pkl", "wb") as f:
    pickle.dump(debug_cmd_encoder, f)

# Dataset
dataset = Dataset.from_pandas(df[["message", "show_cmd_label", "debug_cmd_label"]])

# Tokenization
model_name = "bert-base-uncased"
tokenizer = AutoTokenizer.from_pretrained(model_name)

def tokenize(batch):
    return tokenizer(batch["message"], padding="max_length", truncation=True, max_length=128)

tokenized_dataset = dataset.map(tokenize, batched=True)
tokenized_dataset = tokenized_dataset.train_test_split(test_size=0.1)

# Model for show commands
model_show = BertForSequenceClassification.from_pretrained(model_name, num_labels=len(show_cmd_encoder.classes_))
model_debug = BertForSequenceClassification.from_pretrained(model_name, num_labels=len(debug_cmd_encoder.classes_))

# Training args
args_show = TrainingArguments(
    output_dir="./router_ai_model_bert/show_cmd_model",
    num_train_epochs=4,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    logging_dir="./logs_bert/show",
    logging_steps=10,
)

args_debug = TrainingArguments(
    output_dir="./router_ai_model_bert/debug_cmd_model",
    num_train_epochs=4,
    per_device_train_batch_size=8,
    per_device_eval_batch_size=8,
    logging_dir="./logs_bert/debug",
    logging_steps=10,
)

# Metric
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = torch.argmax(torch.tensor(logits), axis=-1)
    acc = (preds == torch.tensor(labels)).float().mean()
    return {"accuracy": acc.item()}

# Trainer for show
trainer_show = Trainer(
    model=model_show,
    args=args_show,
    train_dataset=tokenized_dataset["train"].rename_column("show_cmd_label", "labels").remove_columns(["debug_cmd_label"]),
    eval_dataset=tokenized_dataset["test"].rename_column("show_cmd_label", "labels").remove_columns(["debug_cmd_label"]),
    compute_metrics=compute_metrics,
    tokenizer=tokenizer
)

# Trainer for debug
trainer_debug = Trainer(
    model=model_debug,
    args=args_debug,
    train_dataset=tokenized_dataset["train"].rename_column("debug_cmd_label", "labels").remove_columns(["show_cmd_label"]),
    eval_dataset=tokenized_dataset["test"].rename_column("debug_cmd_label", "labels").remove_columns(["show_cmd_label"]),
    compute_metrics=compute_metrics,
    tokenizer=tokenizer
)

# Train both
trainer_show.train()
trainer_debug.train()

# Save models and tokenizer
tokenizer.save_pretrained("router_ai_model_bert")
model_show.save_pretrained("router_ai_model_bert/show_cmd_model")
model_debug.save_pretrained("router_ai_model_bert/debug_cmd_model")


# Save trained models
import torch
torch.save(model_show, "router_ai_model_bert/show_model.pt")
torch.save(model_debug, "router_ai_model_bert/debug_model.pt")
