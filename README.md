# PhishGuard AI
## Outsmarting the Next-Generation Cyber Attack

### Team
- V. Vaishnavi — 160124737094
- B. Vathan Reddy — 160124737100
- Chaitanya Bharathi Institute of Technology
- Information Technology

## Fast setup
Because some Windows lab PCs block scikit-learn DLLs, train the model in Google Colab.

1. Open `colab/PhishGuard_AI_Training.ipynb` in Google Colab.
2. Upload the PhiUSIIL CSV when prompted.
3. Run all cells.
4. Download the generated ZIP containing the trained Random Forest model.
5. Extract `phishguard_random_forest.joblib` and `feature_columns.json` into `models/`.
6. In VS Code:
   `pip install -r requirements.txt`
7. Run:
   `streamlit run app.py`

The notebook trains Decision Tree, Random Forest, Naive Bayes and KNN and saves comparison metrics.
